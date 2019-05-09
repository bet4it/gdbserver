#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
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

uint8_t tmpbuf[0x4000];

void sigint_pid()
{
  kill(-threads.t[0].pid, SIGINT);
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
      } while (check_clone());
  threads.curr = cthread;
}

void prepare_resume_reply(uint8_t *buf, bool cont)
{
  if (WIFEXITED(threads.curr->stat))
    sprintf(buf, "W%02x", gdb_signal_from_host(WEXITSTATUS(threads.curr->stat)));
  if (WIFSTOPPED(threads.curr->stat))
  {
    if (cont)
      stop_threads();
    sprintf(buf, "T%02xthread:%02x;", gdb_signal_from_host(WSTOPSIG(threads.curr->stat)), threads.curr->tid);
  }
  // if (WIFSIGNALED(stat_loc))
  //   sprintf(buf, "T%02x", gdb_signal_from_host(WTERMSIG(stat_loc)));
}

void read_auxv(void)
{
  size_t *stack_ptr = entry_stack_ptr;
  size_t argc = ptrace(PTRACE_PEEKDATA, threads.curr->pid, stack_ptr, NULL);
  stack_ptr += argc + 1;
  size_t null_ptr = ptrace(PTRACE_PEEKDATA, threads.curr->pid, stack_ptr, NULL);
  assert(!null_ptr);
  stack_ptr++;

  while (ptrace(PTRACE_PEEKDATA, threads.curr->pid, (void *)stack_ptr, NULL))
    stack_ptr++;
  stack_ptr++;

  size_t auxv_data[1024];
  size_t *ptr = auxv_data;
  while (1)
  {
    *(ptr++) = ptrace(PTRACE_PEEKDATA, threads.curr->pid, (stack_ptr++), NULL);
    *(ptr++) = ptrace(PTRACE_PEEKDATA, threads.curr->pid, (stack_ptr++), NULL);
    if (!(*(ptr - 1) || *(ptr - 2)))
      break;
  }
  write_binary_packet("l", (uint8_t *)auxv_data, (ptr - auxv_data) * sizeof(size_t));
}

void process_xfer(const char *name, char *args)
{
  const char *mode = args;
  args = strchr(args, ':');
  *args++ = '\0';
  if (!strcmp(name, "features") && !strcmp(mode, "read"))
    write_packet("l<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>");
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
  uint8_t buf[1024];

  args = strchr(payload, ':');
  if (args)
    *args++ = '\0';
  name = payload;
  if (!strcmp(name, "C"))
  {
    snprintf(buf, sizeof(buf), "QC%02x", threads.curr->tid);
    write_packet(buf);
  }
  if (!strcmp(name, "Attached"))
    write_packet("1");
  if (!strcmp(name, "Offsets"))
    write_packet("");
  if (!strcmp(name, "Supported"))
    write_packet("PacketSize=8000;qXfer:features:read+;qXfer:auxv:read+;qXfer:exec-file:read+");
  if (!strcmp(name, "Symbol"))
  {
    const char *colon = strchr(args, ':');
    int has_address;
    size_t address;
    assert(colon != NULL);
    if (*args == ':')
      has_address = 0;
    else
    {
      has_address = 1;
      address = strtoul(args, &args, 16);
    }
    assert(*args == ':');
    ++args;
    write_packet("OK");
  }
  if (strstr(name, "ThreadExtraInfo") == name)
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
    assert(threads.len > 0);
    strcpy(buf, "m");
    for (int i = 0; i < threads.len; i++, ptr++)
    {
      while (!ptr->tid)
        ptr++;
      snprintf(tmpbuf, sizeof(tmpbuf), "%02x,", ptr->tid);
      strcat(buf, tmpbuf);
    }
    buf[strlen(buf) - 1] = '\0';
    write_packet(buf);
  }
  if (!strcmp(name, "sThreadInfo"))
    write_packet("l");
}

static int gdb_open_flags_to_system_flags(int64_t flags)
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

  assert(!(flags & ~(int64_t)(3 | 0x8 | 0x200 | 0x400 | 0x800)));

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
  {
    *args++ = '\0';
  }
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
      } while (check_exit() || check_clone());
      prepare_resume_reply(tmpbuf, true);
      write_packet(tmpbuf);
    }
    if (args[0] == 's')
    {
      assert(args[1] == ':');
      pid_t tid = strtol(args + 2, NULL, 16);
      set_curr_thread(tid);
      ptrace(PTRACE_SINGLESTEP, threads.curr->tid, NULL, NULL);
      waitpid(threads.curr->tid, &threads.curr->stat, __WALL);
      prepare_resume_reply(tmpbuf, false);
      write_packet(tmpbuf);
    }
  }
  if (!strcmp("Cont?", name))
    write_packet("vCont;c;C;s;S;");
  if (!strcmp("MustReplyEmpty", name))
    write_packet("");
  if (name == strstr(name, "File:"))
  {
    char *operation = payload + 5;
    if (operation == strstr(operation, "open:"))
    {
      char file_name[128];
      char *file_name_end = strchr(operation + 5, ',');
      int file_name_len;
      assert(file_name_end != NULL);
      *file_name_end = 0;
      assert((file_name_len = strlen(operation + 5)) < 128);
      hex2mem(operation + 5, file_name, file_name_len);
      file_name[file_name_len / 2] = '\0';
      char *flags_end;
      int64_t flags = strtol(file_name_end + 1, &flags_end, 16);
      assert(*flags_end == ',');
      flags = gdb_open_flags_to_system_flags(flags);
      char *mode_end;
      int64_t mode = strtol(flags_end + 1, &mode_end, 16);
      assert(*mode_end == 0);
      assert((mode & ~(int64_t)0777) == 0);
      int fd;
      fd = open(file_name, flags, mode);
      char ret_buf[20];
      sprintf(ret_buf, "F%d", fd);
      write_packet(ret_buf);
    }
    else if (operation == strstr(operation, "close:"))
    {
      char *endptr;
      int64_t fd = strtol(operation + 6, &endptr, 16);
      assert(*endptr == 0);
      close(fd);
      write_packet("F0");
    }
    else if (operation == strstr(operation, "pread:"))
    {
      char *fd_end;
      int fd = strtol(operation + 6, &fd_end, 16);
      assert(*fd_end == ',');
      char *size_end;
      int size = strtol(fd_end + 1, &size_end, 16);
      assert(*size_end == ',');
      assert(size >= 0);
      if (size * 2 > PACKET_BUF_SIZE)
        size = PACKET_BUF_SIZE / 2;
      char *offset_end;
      int offset = strtol(size_end + 1, &offset_end, 16);
      assert(*offset_end == 0);
      assert(offset >= 0);
      char *buf = malloc(size);
      int ret = pread(fd, buf, size, offset);
      char resbuf[32];
      sprintf(resbuf, "F%x;", ret);
      write_binary_packet(resbuf, buf, ret);
      free(buf);
    }
    else if (operation == strstr(operation, "setfs:"))
    {
      char *endptr;
      int64_t pid = strtol(operation + 6, &endptr, 16);
      assert(*endptr == 0);
      assert(pid == 0);
      write_packet("F0");
    }
    else
      write_packet("");
  }
}

int set_breakpoint(pid_t tid, size_t addr, size_t length)
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
    return -1;
  else
    return 0;
}

int remove_breakpoint(pid_t tid, size_t addr, size_t length)
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
    return -1;
  else
    return 0;
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
  case 'g':
  {
    struct user_regs_struct regs;
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
      tid = strtol(payload, NULL, 16);
      if (tid > 0)
        set_curr_thread(tid);
    }
    write_packet("OK");
    break;
  case 'm':
  case 'M':
  {
    size_t maddr, mlen, mdata;
    maddr = strtoul(payload, &payload, 16);
    assert(',' == *payload++);
    mlen = strtoul(payload, &payload, 16);
    assert('\0' == *payload++);
    if (request == 'm')
    {
      for (int i = 0; i < mlen; i += 8)
      {
        mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
        mem2hex((void *)&mdata, tmpbuf + i * 2, (mlen - i >= 8 ? 8 : mlen - i));
      }
      tmpbuf[mlen * 2] = '\0';
      write_packet(tmpbuf);
    }
    else
    {
      for (int i = 0; i < mlen; i += 8)
      {
        if (mlen - i >= 8)
          hex2mem(payload + i * 2, (void *)&mdata, 8);
        else
        {
          mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
          hex2mem(payload + i * 2, (void *)&mdata, mlen - i);
        }
        ptrace(PTRACE_POKEDATA, threads.curr->tid, maddr + i, mdata);
      }
      write_packet("OK");
    }
    break;
  }
  case 'p':
  {
    int i = strtol(payload, NULL, 16);
    if (i > ARCH_REG_NUM)
    {
      write_packet("E01");
      break;
    }
    size_t regdata = ptrace(PTRACE_PEEKUSER, threads.curr->tid, 8 * regs_map[i].idx, NULL);
    mem2hex((void *)&regdata, tmpbuf, regs_map[i].size);
    tmpbuf[regs_map[i].size * 2] = '\0';
    write_packet(tmpbuf);
    break;
  }
  case 'P':
  {
    int i = strtol(payload, &payload, 16);
    assert('=' == *payload++);
    if (i > ARCH_REG_NUM && i != 57)
    {
      write_packet("E01");
      break;
    }
    size_t regdata;
    hex2mem(payload, (void *)&regdata, 8 * 2);
    if (i == 57)
      ptrace(PTRACE_POKEUSER, threads.curr->tid, 8 * ORIG_RAX, regdata);
    else
      ptrace(PTRACE_POKEUSER, threads.curr->tid, 8 * regs_map[i].idx, regdata);
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
    int new_len;
    maddr = strtoul(payload, &payload, 16);
    assert(',' == *payload++);
    mlen = strtoul(payload, &payload, 16);
    assert(':' == *payload++);
    new_len = unescape(payload, (char *)packetend_ptr - payload);
    assert(new_len == mlen);
    for (int i = 0; i < mlen; i += 8)
    {
      if (mlen - i >= 8)
        memcpy((void *)&mdata, payload + i, 8);
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
  case 'z':
  case 'Z':
  {
    int type = strtol(payload, &payload, 16);
    assert(',' == *payload++);
    size_t addr = strtoul(payload, &payload, 16);
    assert(',' == *payload);
    payload++;
    size_t length = strtoul(payload, &payload, 16);
    if (type == 0)
    {
      int ret;
      if (request == 'Z')
        ret = set_breakpoint(threads.curr->tid, addr, length);
      else
        ret = remove_breakpoint(threads.curr->tid, addr, length);
      if (ret == 0)
        write_packet("OK");
      else
        write_packet("E01");
    }
    else
      write_packet("");
    break;
  }
  case '?':
    prepare_resume_reply(tmpbuf, false);
    write_packet(tmpbuf);
    break;
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
  pid_t pid = fork();
  char *prog = argv[1];
  if (pid == 0)
  {
    setpgrp();
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl(prog, prog, NULL);
  }
  else if (pid >= 1)
  {
    pid_t tid;
    int stat;
    initialize_async_io(sigint_pid);
    threads.t[0].pid = threads.t[0].tid = pid;
    threads.curr = &threads.t[0];
    threads.len = 1;
    tid = waitpid(-1, &stat, __WALL);
    assert(threads.curr->tid == tid);
    threads.curr->stat = stat;
    ptrace(PTRACE_SETOPTIONS, threads.curr->tid, NULL, PTRACE_O_TRACECLONE);
    entry_stack_ptr = (size_t *)ptrace(PTRACE_PEEKUSER, threads.curr->tid, 8 * RSP, NULL);
    get_connection();
    get_request();
  }
  return 0;
}
