#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "arch.h"
#include "utils.h"
#include "packets.h"
#include "gdb_signals.h"

size_t *entry_stack_ptr;

#define THREAD_NUMBER 64

struct thread_id_t
{
  pid_t pid;
  pid_t tid;
  int stat;
};

struct thread_list_t
{
  struct thread_id_t t[THREAD_NUMBER];
  struct thread_id_t *curr;
  int len;
} threads;

#define BREAKPOINT_NUMBER 64

struct debug_breakpoint_t
{
  size_t addr;
  size_t orig_data;
} breakpoints[BREAKPOINT_NUMBER];

uint8_t tmpbuf[0x20000];
bool attach = false;

void sigint_pid()
{
  kill(attach ? threads.t[0].pid : -threads.t[0].pid, SIGINT);
}

bool is_clone_event(int status)
{
  return (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)));
}

bool check_exit()
{
  if (WIFEXITED(threads.curr->stat) && threads.len > 1)
  {
    threads.curr->pid = 0;
    threads.curr->tid = 0;
    threads.curr = NULL;
    threads.len--;
    return true;
  }
  return false;
}

void check_sigtrap()
{
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, threads.curr->tid, NULL, &info);
  if (info.si_code == SI_KERNEL && info.si_signo == SIGTRAP)
  {
    size_t pc = ptrace(PTRACE_PEEKUSER, threads.curr->tid, SZ * PC, NULL);
    pc -= sizeof(break_instr);
    for (int i = 0; i < BREAKPOINT_NUMBER; i++)
      if (breakpoints[i].addr == pc)
      {
        ptrace(PTRACE_POKEUSER, threads.curr->tid, SZ * PC, pc);
        break;
      }
  }
}

bool check_sigstop()
{
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, threads.curr->tid, NULL, &info);
  if (info.si_code == SI_TKILL && info.si_signo == SIGSTOP)
  {
    ptrace(PTRACE_CONT, threads.curr->tid, NULL, NULL);
    return true;
  }
  return false;
}

bool check_clone()
{
  if (is_clone_event(threads.curr->stat))
  {
    size_t newtid;
    int stat;
    ptrace(PTRACE_GETEVENTMSG, threads.curr->tid, NULL, (long)&newtid);
    if (waitpid(newtid, &stat, __WALL) > 0)
    {
      for (int i = 0; i < THREAD_NUMBER; i++)
        if (!threads.t[i].tid)
        {
          threads.t[i].pid = threads.curr->pid;
          threads.t[i].tid = newtid;
          threads.len++;
          break;
        }
      ptrace(PTRACE_CONT, newtid, NULL, NULL);
    }
    ptrace(PTRACE_CONT, threads.curr->tid, NULL, NULL);
    return true;
  }
  return false;
}

void set_curr_thread(pid_t tid)
{
  for (int i = 0; i < THREAD_NUMBER; i++)
    if (threads.t[i].tid == tid)
    {
      threads.curr = &threads.t[i];
      break;
    }
}

void stop_threads()
{
  struct thread_id_t *cthread = threads.curr;
  for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len - 1; i++)
    if (threads.t[i].pid && threads.t[i].tid != cthread->tid)
      do
      {
        threads.curr = &threads.t[i];
        if (syscall(SYS_tgkill, threads.curr->pid, threads.curr->tid, SIGSTOP) == -1)
          printf("Failed to stop thread %d\n", threads.curr->tid);
        waitpid(threads.curr->tid, &threads.curr->stat, __WALL);
        check_exit();
        check_sigtrap();
      } while (check_clone());
  threads.curr = cthread;
}

size_t init_tids(const pid_t pid)
{
  char dirname[64];
  DIR *dir;
  struct dirent *ent;
  int i = 0;

  snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid);
  dir = opendir(dirname);
  if (!dir)
    perror("opendir()");
  while ((ent = readdir(dir)) != NULL)
  {
    if (ent->d_name[0] == '.')
      continue;
    threads.t[i].pid = pid;
    threads.t[i].tid = atoi(ent->d_name);
    threads.len++;
    i++;
  }
  closedir(dir);
}

void prepare_resume_reply(uint8_t *buf, bool cont)
{
  if (WIFEXITED(threads.curr->stat))
    sprintf(buf, "W%02x", gdb_signal_from_host(WEXITSTATUS(threads.curr->stat)));
  if (WIFSTOPPED(threads.curr->stat))
  {
    if (cont)
      stop_threads();
    sprintf(buf, "T%02xthread:p%02x.%02x;", gdb_signal_from_host(WSTOPSIG(threads.curr->stat)), threads.curr->pid, threads.curr->tid);
  }
  // if (WIFSIGNALED(stat_loc))
  //   sprintf(buf, "T%02x", gdb_signal_from_host(WTERMSIG(stat_loc)));
}

void read_auxv(void)
{
  uint8_t proc_auxv_path[20];
  FILE *fp;
  int ret;
  sprintf(proc_auxv_path, "/proc/%d/auxv", threads.t[0].pid);
  fp = fopen(proc_auxv_path, "r");
  ret = fread(tmpbuf, 1, sizeof(tmpbuf), fp);
  fclose(fp);
  write_binary_packet("l", tmpbuf, ret);
}

void process_xfer(const char *name, char *args)
{
  const char *mode = args;
  args = strchr(args, ':');
  *args++ = '\0';
  if (!strcmp(name, "features") && !strcmp(mode, "read"))
    write_packet(FEATURE_STR);
  if (!strcmp(name, "auxv") && !strcmp(mode, "read"))
    read_auxv();
  if (!strcmp(name, "exec-file") && !strcmp(mode, "read"))
  {
    uint8_t proc_exe_path[20], file_path[256] = {'l'};
    sprintf(proc_exe_path, "/proc/%d/exe", threads.t[0].pid);
    realpath(proc_exe_path, file_path + 1);
    write_packet(file_path);
  }
}

void process_query(char *payload)
{
  const char *name;
  char *args;

  args = strchr(payload, ':');
  if (args)
    *args++ = '\0';
  name = payload;
  if (!strcmp(name, "C"))
  {
    snprintf(tmpbuf, sizeof(tmpbuf), "QCp%02x.%02x", threads.curr->pid, threads.curr->tid);
    write_packet(tmpbuf);
  }
  if (!strcmp(name, "Attached"))
  {
    if (attach)
      write_packet("1");
    else
      write_packet("0");
  }
  if (!strcmp(name, "Offsets"))
    write_packet("");
  if (!strcmp(name, "Supported"))
    write_packet("PacketSize=8000;qXfer:features:read+;qXfer:auxv:read+;qXfer:exec-file:read+;multiprocess+");
  if (!strcmp(name, "Symbol"))
    write_packet("OK");
  if (name == strstr(name, "ThreadExtraInfo"))
  {
    args = payload;
    args = 1 + strchr(args, ',');
    write_packet("41414141");
  }
  if (!strcmp(name, "TStatus"))
    write_packet("");
  if (!strcmp(name, "Xfer"))
  {
    name = args;
    args = strchr(args, ':');
    *args++ = '\0';
    return process_xfer(name, args);
  }
  if (!strcmp(name, "fThreadInfo"))
  {
    struct thread_id_t *ptr = threads.t;
    uint8_t pid_buf[20];
    assert(threads.len > 0);
    strcpy(tmpbuf, "m");
    for (int i = 0; i < threads.len; i++, ptr++)
    {
      while (!ptr->tid)
        ptr++;
      snprintf(pid_buf, sizeof(pid_buf), "p%02x.%02x,", ptr->pid, ptr->tid);
      strcat(tmpbuf, pid_buf);
    }
    tmpbuf[strlen(tmpbuf) - 1] = '\0';
    write_packet(tmpbuf);
  }
  if (!strcmp(name, "sThreadInfo"))
    write_packet("l");
}

static int gdb_open_flags_to_system_flags(size_t flags)
{
  int ret;
  switch (flags & 3)
  {
  case 0:
    ret = O_RDONLY;
    break;
  case 1:
    ret = O_WRONLY;
    break;
  case 2:
    ret = O_RDWR;
    break;
  default:
    assert(0);
    return 0;
  }

  assert(!(flags & ~(size_t)(3 | 0x8 | 0x200 | 0x400 | 0x800)));

  if (flags & 0x8)
    ret |= O_APPEND;
  if (flags & 0x200)
    ret |= O_CREAT;
  if (flags & 0x400)
    ret |= O_TRUNC;
  if (flags & 0x800)
    ret |= O_EXCL;
  return ret;
}

void process_vpacket(char *payload)
{
  const char *name;
  char *args;
  args = strchr(payload, ';');
  if (args)
    *args++ = '\0';
  name = payload;

  if (!strcmp("Cont", name))
  {
    if (args[0] == 'c')
    {
      for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len; i++)
        if (threads.t[i].tid)
        {
          ptrace(PTRACE_CONT, threads.t[i].tid, NULL, NULL);
          n++;
        }
      do
      {
        pid_t tid;
        int stat;
        enable_async_io();
        tid = waitpid(-1, &stat, __WALL);
        set_curr_thread(tid);
        threads.curr->stat = stat;
        disable_async_io();
      } while (check_exit() || check_sigstop() || check_clone());
      prepare_resume_reply(tmpbuf, true);
      write_packet(tmpbuf);
    }
    if (args[0] == 's')
    {
      assert(args[1] == ':');
      char *dot = strchr(args, '.');
      assert(dot);
      pid_t tid = strtol(dot + 1, NULL, 16);
      set_curr_thread(tid);
      ptrace(PTRACE_SINGLESTEP, threads.curr->tid, NULL, NULL);
      waitpid(threads.curr->tid, &threads.curr->stat, __WALL);
      prepare_resume_reply(tmpbuf, false);
      write_packet(tmpbuf);
    }
  }
  if (!strcmp("Cont?", name))
    write_packet("vCont;c;C;s;S;");
  if (!strcmp("Kill", name))
  {
    kill(-threads.t[0].pid, SIGKILL);
    write_packet("OK");
  }
  if (!strcmp("MustReplyEmpty", name))
    write_packet("");
  if (name == strstr(name, "File:"))
  {
    char *operation = strchr(name, ':') + 1;
    if (operation == strstr(operation, "open:"))
    {
      char result[10];
      char *parameter = strchr(operation, ':') + 1;
      char *end = strchr(parameter, ',');
      int len, fd;
      size_t flags, mode;
      assert(end != NULL);
      *end = 0;
      len = strlen(parameter);
      hex2mem(parameter, tmpbuf, len);
      tmpbuf[len / 2] = '\0';
      parameter += len + 1;
      assert(sscanf(parameter, "%zx,%zx", &flags, &mode) == 2);
      flags = gdb_open_flags_to_system_flags(flags);
      assert((mode & ~(int64_t)0777) == 0);
      fd = open(tmpbuf, flags, mode);
      sprintf(result, "F%x", fd);
      write_packet(result);
    }
    else if (operation == strstr(operation, "close:"))
    {
      char *parameter = strchr(operation, ':') + 1;
      size_t fd;
      assert(sscanf(parameter, "%zx", &fd) == 1);
      close(fd);
      write_packet("F0");
    }
    else if (operation == strstr(operation, "pread:"))
    {
      char *parameter = strchr(operation, ':') + 1;
      size_t fd, size, offset;
      assert(sscanf(parameter, "%zx,%zx,%zx", &fd, &size, &offset) == 3);
      assert(size >= 0);
      if (size * 2 > PACKET_BUF_SIZE)
        size = PACKET_BUF_SIZE / 2;
      assert(offset >= 0);
      char *buf = malloc(size);
      FILE *fp = fdopen(fd, "rb");
      fseek(fp, offset, SEEK_SET);
      int ret = fread(buf, 1, size, fp);
      sprintf(tmpbuf, "F%x;", ret);
      write_binary_packet(tmpbuf, buf, ret);
      free(buf);
    }
    else if (operation == strstr(operation, "setfs:"))
    {
      char *endptr;
      int64_t pid = strtol(operation + 6, &endptr, 16);
      assert(*endptr == 0);
      write_packet("F0");
    }
    else
      write_packet("");
  }
}

bool set_breakpoint(pid_t tid, size_t addr, size_t length)
{
  int i;
  for (i = 0; i < BREAKPOINT_NUMBER; i++)
    if (breakpoints[i].addr == 0)
    {
      size_t data = ptrace(PTRACE_PEEKDATA, tid, (void *)addr, NULL);
      breakpoints[i].orig_data = data;
      breakpoints[i].addr = addr;
      assert(sizeof(break_instr) <= length);
      memcpy((void *)&data, break_instr, sizeof(break_instr));
      ptrace(PTRACE_POKEDATA, tid, (void *)addr, data);
      break;
    }
  if (i == BREAKPOINT_NUMBER)
    return false;
  else
    return true;
}

bool remove_breakpoint(pid_t tid, size_t addr, size_t length)
{
  int i;
  for (i = 0; i < BREAKPOINT_NUMBER; i++)
    if (breakpoints[i].addr == addr)
    {
      ptrace(PTRACE_POKEDATA, tid, (void *)addr, breakpoints[i].orig_data);
      breakpoints[i].addr = 0;
      break;
    }
  if (i == BREAKPOINT_NUMBER)
    return false;
  else
    return true;
}

size_t restore_breakpoint(size_t addr, size_t length, size_t data)
{
  for (int i = 0; i < BREAKPOINT_NUMBER; i++)
  {
    size_t bp_addr = breakpoints[i].addr;
    size_t bp_size = sizeof(break_instr);
    if (bp_addr && bp_addr + bp_size > addr && bp_addr < addr + length)
    {
      for (size_t j = 0; j < bp_size; j++)
      {
        if (bp_addr + j >= addr && bp_addr + j < addr + length)
          ((uint8_t *)&data)[bp_addr + j - addr] = ((uint8_t *)&breakpoints[i].orig_data)[j];
      }
    }
  }
  return data;
}

void process_packet()
{
  uint8_t *inbuf = inbuf_get();
  int inbuf_size = inbuf_end();
  uint8_t *packetend_ptr = (uint8_t *)memchr(inbuf, '#', inbuf_size);
  int packetend = packetend_ptr - inbuf;
  assert('$' == inbuf[0]);
  char request = inbuf[1];
  char *payload = (char *)&inbuf[2];
  inbuf[packetend] = '\0';

  uint8_t checksum = 0;
  uint8_t checksum_str[3];
  for (int i = 1; i < packetend; i++)
    checksum += inbuf[i];
  assert(checksum == (hex(inbuf[packetend + 1]) << 4 | hex(inbuf[packetend + 2])));

  switch (request)
  {
  case 'D':
    for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len; i++)
      if (threads.t[i].tid)
        if (ptrace(PTRACE_DETACH, threads.t[i].tid, NULL, NULL) < 0)
          perror("ptrace()");
    exit(0);
  case 'g':
  {
    regs_struct regs;
    uint8_t regbuf[20];
    tmpbuf[0] = '\0';
    ptrace(PTRACE_GETREGS, threads.curr->tid, NULL, &regs);
    for (int i = 0; i < ARCH_REG_NUM; i++)
    {
      mem2hex((void *)(((size_t *)&regs) + regs_map[i].idx), regbuf, regs_map[i].size);
      regbuf[regs_map[i].size * 2] = '\0';
      strcat(tmpbuf, regbuf);
    }
    write_packet(tmpbuf);
    break;
  }
  case 'H':
    if ('g' == *payload++)
    {
      pid_t tid;
      char *dot = strchr(payload, '.');
      assert(dot);
      tid = strtol(dot, NULL, 16);
      if (tid > 0)
        set_curr_thread(tid);
    }
    write_packet("OK");
    break;
  case 'm':
  {
    size_t maddr, mlen, mdata;
    assert(sscanf(payload, "%zx,%zx", &maddr, &mlen) == 2);
    if (mlen * SZ * 2 > 0x20000)
    {
      puts("Buffer overflow!");
      exit(-1);
    }
    for (int i = 0; i < mlen; i += SZ)
    {
      errno = 0;
      mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
      if (errno)
      {
        sprintf(tmpbuf, "E%02x", errno);
        break;
      }
      mdata = restore_breakpoint(maddr, sizeof(size_t), mdata);
      mem2hex((void *)&mdata, tmpbuf + i * 2, (mlen - i >= SZ ? SZ : mlen - i));
    }
    tmpbuf[mlen * 2] = '\0';
    write_packet(tmpbuf);
    break;
  }
  case 'M':
  {
    size_t maddr, mlen, mdata;
    assert(sscanf(payload, "%zx,%zx", &maddr, &mlen) == 2);
    for (int i = 0; i < mlen; i += SZ)
    {
      if (mlen - i >= SZ)
        hex2mem(payload + i * 2, (void *)&mdata, SZ);
      else
      {
        mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
        hex2mem(payload + i * 2, (void *)&mdata, mlen - i);
      }
      ptrace(PTRACE_POKEDATA, threads.curr->tid, maddr + i, mdata);
    }
    write_packet("OK");
    break;
  }
  case 'p':
  {
    int i = strtol(payload, NULL, 16);
    if (i >= ARCH_REG_NUM && i != EXTRA_NUM)
    {
      write_packet("E01");
      break;
    }
    size_t regdata;
    if (i == EXTRA_NUM)
    {
      regdata = ptrace(PTRACE_PEEKUSER, threads.curr->tid, SZ * EXTRA_REG, NULL);
      mem2hex((void *)&regdata, tmpbuf, EXTRA_SIZE);
      tmpbuf[EXTRA_SIZE * 2] = '\0';
    }
    else
    {
      regdata = ptrace(PTRACE_PEEKUSER, threads.curr->tid, SZ * regs_map[i].idx, NULL);
      mem2hex((void *)&regdata, tmpbuf, regs_map[i].size);
      tmpbuf[regs_map[i].size * 2] = '\0';
    }
    write_packet(tmpbuf);
    break;
  }
  case 'P':
  {
    int i = strtol(payload, &payload, 16);
    assert('=' == *payload++);
    if (i >= ARCH_REG_NUM && i != EXTRA_NUM)
    {
      write_packet("E01");
      break;
    }
    size_t regdata = 0;
    hex2mem(payload, (void *)&regdata, SZ * 2);
    if (i == EXTRA_NUM)
      ptrace(PTRACE_POKEUSER, threads.curr->tid, SZ * EXTRA_REG, regdata);
    else
      ptrace(PTRACE_POKEUSER, threads.curr->tid, SZ * regs_map[i].idx, regdata);
    write_packet("OK");
    break;
  }
  case 'q':
    process_query(payload);
    break;
  case 'v':
    process_vpacket(payload);
    break;
  case 'X':
  {
    size_t maddr, mlen, mdata;
    int offset, new_len;
    assert(sscanf(payload, "%zx,%zx:%n", &maddr, &mlen, &offset) == 2);
    payload += offset;
    new_len = unescape(payload, (char *)packetend_ptr - payload);
    assert(new_len == mlen);
    for (int i = 0; i < mlen; i += SZ)
    {
      if (mlen - i >= SZ)
        memcpy((void *)&mdata, payload + i, SZ);
      else
      {
        mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
        memcpy((void *)&mdata, payload + i, mlen - i);
      }
      ptrace(PTRACE_POKEDATA, threads.curr->tid, maddr + i, mdata);
    }
    write_packet("OK");
    break;
  }
  case 'Z':
  {
    size_t type, addr, length;
    assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr, &length) == 3);
    if (type == 0 && sizeof(break_instr))
    {
      bool ret = set_breakpoint(threads.curr->tid, addr, length);
      if (ret)
        write_packet("OK");
      else
        write_packet("E01");
    }
    else
      write_packet("");
    break;
  }
  case 'z':
  {
    size_t type, addr, length;
    assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr, &length) == 3);
    if (type == 0)
    {
      bool ret = remove_breakpoint(threads.curr->tid, addr, length);
      if (ret)
        write_packet("OK");
      else
        write_packet("E01");
    }
    else
      write_packet("");
    break;
  }
  case '?':
    write_packet("S05");
    break;
  default:
    write_packet("");
  }

  inbuf_erase_head(packetend + 3);
}

void get_request()
{
  while (true)
  {
    read_packet();
    process_packet();
    write_flush();
  }
}

int main(int argc, char *argv[])
{
  pid_t pid;
  char **next_arg = &argv[1];
  char *arg_end, *target = NULL;
  int stat;

  if (*next_arg != NULL && strcmp(*next_arg, "--attach") == 0)
  {
    attach = true;
    next_arg++;
  }

  target = *next_arg;
  next_arg++;

  if (target == NULL || *next_arg == NULL)
  {
    printf("Usage : gdbserver 127.0.0.1:1234 a.out or gdbserver --attach 127.0.0.1:1234 2468\n");
    exit(-1);
  }

  if (attach)
  {
    pid = atoi(*next_arg);
    init_tids(pid);
    for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len; i++)
      if (threads.t[i].tid)
      {
        if (ptrace(PTRACE_ATTACH, threads.t[i].tid, NULL, NULL) < 0)
        {
          perror("ptrace()");
          return -1;
        }
        if (waitpid(threads.t[i].tid, &threads.t[i].stat, __WALL) < 0)
        {
          perror("waitpid");
          return -1;
        }
        ptrace(PTRACE_SETOPTIONS, threads.t[i].tid, NULL, PTRACE_O_TRACECLONE);
        n++;
      }
  }
  else
  {
    pid = fork();
    if (pid == 0)
    {
      char **args = next_arg;
      setpgrp();
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execvp(args[0], args);
      perror(args[0]);
      _exit(1);
    }
    if (waitpid(pid, &stat, __WALL) < 0)
    {
      perror("waitpid");
      return -1;
    }
    threads.t[0].pid = threads.t[0].tid = pid;
    threads.t[0].stat = stat;
    threads.len = 1;
    int options = PTRACE_O_TRACECLONE;
#ifdef PTRACE_O_EXITKILL
    options |= PTRACE_O_EXITKILL;
#endif
    ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
  }
  threads.curr = &threads.t[0];
  initialize_async_io(sigint_pid);
  remote_prepare(target);
  get_request();
  return 0;
}
