#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "arch.h"
#include "utils.h"
#include "packets.h"
#include "gdb_signals.h"

int stat_loc;

#define THREAD_NUMBER 64

struct thread_id_t
{
  pid_t pid;
  pid_t tid;
};

struct thread_list_t
{
  struct thread_id_t t[THREAD_NUMBER];
  struct thread_id_t curr;
  int len;
} threads;

#define BREAKPOINT_NUMBER 64

struct debug_breakpoint_t
{
  size_t addr;
  size_t orig_data;
} breakpoints[BREAKPOINT_NUMBER];

void sigint_pid()
{
  kill(threads.curr.pid, SIGINT);
}

bool is_clone_event(int status)
{
  return (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)));
}

bool check_clone()
{
  if (is_clone_event(stat_loc))
  {
    size_t newtid;
    ptrace(PTRACE_GETEVENTMSG, threads.curr.tid, NULL, (long)&newtid);
    if (waitpid(newtid, &stat_loc, __WALL) > 0)
    {
      for (int i = 0; i < THREAD_NUMBER; i++)
        if (!threads.t[i].tid)
        {
          threads.t[i].pid = threads.curr.pid;
          threads.t[i].tid = newtid;
          threads.len++;
          break;
        }
      ptrace(PTRACE_CONT, newtid, NULL, NULL);
    }
    return true;
  }
  return false;
}

void prepare_resume_reply(uint8_t *buf)
{

  if (WIFEXITED(stat_loc))
    sprintf(buf, "W%02x", gdb_signal_from_host(WEXITSTATUS(stat_loc)));
  if (WIFSTOPPED(stat_loc))
    sprintf(buf, "S%02x", gdb_signal_from_host(WSTOPSIG(stat_loc)));
  // if (WIFSIGNALED(stat_loc))
  //   sprintf(buf, "T%02x", gdb_signal_from_host(WTERMSIG(stat_loc)));
}

void process_xfer(const char *name, char *args)
{
  const char *mode = args;
  args = strchr(args, ':');
  *args++ = '\0';
  if (!strcmp(name, "features") && !strcmp(mode, "read"))
  {
    write_packet("l<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>");
  }
}

void process_query(char *payload)
{
  const char *name;
  char *args;
  uint8_t buf[1024];

  args = strchr(payload, ':');
  if (args)
  {
    *args++ = '\0';
  }
  name = payload;
  if (!strcmp(name, "C"))
  {
    snprintf(buf, sizeof(buf), "QC%02x", threads.curr.tid);
    write_packet(buf);
  }
  if (!strcmp(name, "Attached"))
    write_packet("1");
  if (!strcmp(name, "Offsets"))
    write_packet("");
  if (!strcmp(name, "Supported"))
    write_packet("PacketSize=32768;qXfer:features:read+");
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
    uint8_t tmpbuf[32];
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

void process_vpacket(char *payload)
{
  const char *name;
  char *args;
  uint8_t tmpbuf[400];

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
      do
      {
        enable_async_io();
        ptrace(PTRACE_CONT, threads.curr.tid, NULL, NULL);
        threads.curr.tid = waitpid(-1, &stat_loc, __WALL);
        disable_async_io();
      } while (check_clone());
      prepare_resume_reply(tmpbuf);
      write_packet(tmpbuf);
    }
    if (args[0] == 's')
    {
      ptrace(PTRACE_SINGLESTEP, threads.curr.tid, NULL, NULL);
      waitpid(threads.curr.tid, &stat_loc, __WALL);
      prepare_resume_reply(tmpbuf);
      write_packet(tmpbuf);
    }
  }
  if (!strcmp("Cont?", name))
    write_packet("vCont;c;C;s;S;");
  if (!strcmp("MustReplyEmpty", name))
    write_packet("");
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

  uint8_t tmpbuf[400];

  switch (request)
  {
  case 'g':
  {
    struct user_regs_struct regs;
    uint8_t regbuf[20];
    tmpbuf[0] = '\0';
    ptrace(PTRACE_GETREGS, threads.curr.tid, NULL, &regs);
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
        mdata = ptrace(PTRACE_PEEKDATA, threads.curr.tid, maddr + i, NULL);
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
          mdata = ptrace(PTRACE_PEEKDATA, threads.curr.tid, maddr + i, NULL);
          hex2mem(payload + i * 2, (void *)&mdata, mlen - i);
        }
        ptrace(PTRACE_POKEDATA, threads.curr.tid, maddr + i, mdata);
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
    size_t regdata = ptrace(PTRACE_PEEKUSER, threads.curr.tid, 8 * regs_map[i].idx, NULL);
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
      ptrace(PTRACE_POKEUSER, threads.curr.tid, 8 * ORIG_RAX, regdata);
    else
      ptrace(PTRACE_POKEUSER, threads.curr.tid, 8 * regs_map[i].idx, regdata);
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
        mdata = ptrace(PTRACE_PEEKDATA, threads.curr.tid, maddr + i, NULL);
        memcpy((void *)&mdata, payload + i, mlen - i);
      }
      ptrace(PTRACE_POKEDATA, threads.curr.tid, maddr + i, mdata);
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
        ret = set_breakpoint(threads.curr.tid, addr, length);
      else
        ret = remove_breakpoint(threads.curr.tid, addr, length);
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
    prepare_resume_reply(tmpbuf);
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
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl(prog, prog, NULL);
  }
  else if (pid >= 1)
  {
    initialize_async_io(sigint_pid);
    threads.t[0].pid = threads.t[0].tid = pid;
    threads.curr.pid = threads.curr.tid = pid;
    threads.len = 1;
    wait(&stat_loc);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACECLONE);
    get_connection();
    get_request();
  }
  return 0;
}
