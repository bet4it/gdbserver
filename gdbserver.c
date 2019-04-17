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

int pid;
int stat_loc;

#define BREAKPOINT_NUMBER 64

struct debug_breakpoint_t
{
  size_t addr;
  size_t orig_data;
} breakpoints[BREAKPOINT_NUMBER];

void sigint_pid()
{
  kill(pid, SIGINT);
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

  args = strchr(payload, ':');
  if (args)
  {
    *args++ = '\0';
  }
  name = payload;
  if (!strcmp(name, "C"))
    write_packet("QC1234");
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
    write_packet("m1234");
  if (!strcmp(name, "sThreadInfo"))
    write_packet("l");
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
  if (!strcmp("Cont?", name))
    write_packet("");
  if (!strcmp("MustReplyEmpty", name))
    write_packet("");
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

int set_breakpoint(int pid, size_t addr, size_t length)
{
  int i;
  for (i = 0; i < BREAKPOINT_NUMBER; i++)
    if (breakpoints[i].addr == 0)
    {
      size_t data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
      breakpoints[i].orig_data = data;
      breakpoints[i].addr = addr;
      assert(sizeof(break_instr) <= length);
      memcpy((void *)&data, break_instr, sizeof(break_instr));
      ptrace(PTRACE_POKEDATA, pid, (void *)addr, data);
      break;
    }
  if (i == BREAKPOINT_NUMBER)
    return -1;
  else
    return 0;
}

int remove_breakpoint(int pid, size_t addr, size_t length)
{
  int i;
  for (i = 0; i < BREAKPOINT_NUMBER; i++)
    if (breakpoints[i].addr == addr)
    {
      ptrace(PTRACE_POKEDATA, pid, (void *)addr, breakpoints[i].orig_data);
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
  case 'c':
    enable_async_io();
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&stat_loc);
    disable_async_io();
    prepare_resume_reply(tmpbuf);
    write_packet(tmpbuf);
    break;
  case 'g':
  {
    struct user_regs_struct regs;
    uint8_t regbuf[20];
    tmpbuf[0] = '\0';
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
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
        mdata = ptrace(PTRACE_PEEKDATA, pid, maddr + i, NULL);
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
          mdata = ptrace(PTRACE_PEEKDATA, pid, maddr + i, NULL);
          hex2mem(payload + i * 2, (void *)&mdata, mlen - i);
        }
        ptrace(PTRACE_POKEDATA, pid, maddr + i, mdata);
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
    size_t regdata = ptrace(PTRACE_PEEKUSER, pid, 8 * regs_map[i].idx, NULL);
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
      ptrace(PTRACE_POKEUSER, pid, 8 * ORIG_RAX, regdata);
    else
      ptrace(PTRACE_POKEUSER, pid, 8 * regs_map[i].idx, regdata);
    write_packet("OK");
    break;
  }
  case 'q':
    process_query(payload);
    break;
  case 's':
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    wait(&stat_loc);
    prepare_resume_reply(tmpbuf);
    write_packet(tmpbuf);
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
        mdata = ptrace(PTRACE_PEEKDATA, pid, maddr + i, NULL);
        memcpy((void *)&mdata, payload + i, mlen - i);
      }
      ptrace(PTRACE_POKEDATA, pid, maddr + i, mdata);
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
        ret = set_breakpoint(pid, addr, length);
      else
        ret = remove_breakpoint(pid, addr, length);
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
  pid = fork();
  char *prog = argv[1];
  if (pid == 0)
  {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl(prog, prog, NULL);
  }
  else if (pid >= 1)
  {
    initialize_async_io(sigint_pid);
    wait(&stat_loc);
    get_connection();
    get_request();
  }
  return 0;
}
