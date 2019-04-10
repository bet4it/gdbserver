#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "gdb_signals.h"

static const char INTERRUPT_CHAR = '\x03';

uint8_t reg_map[] = {10, 5, 11, 12, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16, 18, 17, 20, 23, 24, 25, 26};
uint8_t reg_size[] = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 4};
uint8_t break_instr[] = {0xcc};
uint8_t inbuf[32768];
uint8_t outbuf[32768];
int inbufpos;
int outbufpos;
int pid;
int stat_loc;

struct debug_breakpoint_t
{
  size_t addr;
  size_t orig_data;
} breakpoints[10];

int poll_socket(int sock_fd, short events)
{
  struct pollfd pfd;

  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = sock_fd;
  pfd.events = events;

  int ret = poll(&pfd, 1, -1);
  if (ret < 0)
  {
    perror("poll() failed");
    exit(-1);
  }
}

int poll_incoming(int sock_fd)
{
  return poll_socket(sock_fd, POLLIN);
}

int poll_outgoing(int sock_fd)
{
  return poll_socket(sock_fd, POLLOUT);
}

void write_data_raw(const uint8_t *data, ssize_t len)
{
  assert(outbufpos + len < sizeof(outbuf));
  memcpy(outbuf + outbufpos, data, len);
  outbufpos += len;
}

void write_hex(unsigned long hex)
{
  char buf[32];
  size_t len;

  len = snprintf(buf, sizeof(buf) - 1, "%02lx", hex);
  write_data_raw((uint8_t *)buf, len);
}

void write_packet_bytes(const uint8_t *data, size_t num_bytes)
{
  uint8_t checksum;
  size_t i;

  write_data_raw((uint8_t *)"$", 1);
  for (i = 0, checksum = 0; i < num_bytes; ++i)
  {
    checksum += data[i];
  }
  write_data_raw((uint8_t *)data, num_bytes);
  write_data_raw((uint8_t *)"#", 1);
  write_hex(checksum);
}

void write_packet(const char *data)
{
  write_packet_bytes((const uint8_t *)data, strlen(data));
}

void write_flush(int sock_fd)
{
  size_t write_index = 0;
  while (write_index < outbufpos)
  {
    ssize_t nwritten;
    poll_outgoing(sock_fd);
    nwritten = write(sock_fd, outbuf + write_index, outbufpos - write_index);
    if (nwritten < 0)
    {
      printf("Write error\n");
      exit(-2);
    }
    write_index += nwritten;
  }
  outbufpos = 0;
}

void read_data_once(int sock_fd)
{
  int ret;
  ssize_t nread;
  uint8_t buf[4096];

  poll_incoming(sock_fd);
  nread = read(sock_fd, buf, sizeof(buf));
  if (nread <= 0)
  {
    puts("Connection closed");
    exit(0);
  }
  if (inbufpos + nread >= sizeof(inbuf))
  {
    puts("Read buffer overflow");
    exit(-2);
  }
  memcpy(inbuf + inbufpos, buf, nread);
  inbufpos += nread;
}

int skip_to_packet_start()
{
  ssize_t end = -1;
  for (size_t i = 0; i < inbufpos; ++i)
  {
    if (inbuf[i] == '$' || inbuf[i] == INTERRUPT_CHAR)
    {
      end = i;
      break;
    }
  }

  if (end < 0)
  {
    inbufpos = 0;
    return 0;
  }
  memmove(inbuf, inbuf + end, inbufpos - end);
  inbufpos -= end;

  assert(1 <= inbufpos);
  assert('$' == inbuf[0] || INTERRUPT_CHAR == inbuf[0]);
  return 1;
}

void read_packet(int sock_fd)
{
  while (!skip_to_packet_start())
    read_data_once(sock_fd);
  write_data_raw((uint8_t *)"+", 1);
  write_flush(sock_fd);
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
  if (!strcmp(name, "Supported"))
    write_packet("PacketSize=32768;qXfer:features:read+");
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
  {
    write_packet("");
  }
  if (!strcmp("MustReplyEmpty", name))
  {
    write_packet("");
  }
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
  for (i = 0; i < 10; i++)
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
  if (i == 10)
    return -1;
  else
    return 0;
}

int remove_breakpoint(int pid, size_t addr, size_t length)
{
  int i;
  for (i = 0; i < 10; i++)
    if (breakpoints[i].addr == addr)
    {
      ptrace(PTRACE_POKEDATA, pid, (void *)addr, breakpoints[i].orig_data);
      breakpoints[i].addr = 0;
      break;
    }
  if (i == 10)
    return -1;
  else
    return 0;
}

void process_packet()
{
  uint8_t *packetend_ptr = (uint8_t *)memchr(inbuf, '#', inbufpos);
  int packetend = packetend_ptr - inbuf;
  assert('$' == inbuf[0]);
  char request = inbuf[1];
  char *payload = (char *)&inbuf[2];
  inbuf[packetend] = '\0';

  uint8_t checksum = 0;
  uint8_t checksum_str[3];
  for (int i = 1; i < packetend; i++)
    checksum += inbuf[i];
  snprintf(checksum_str, 3, "%02lx", checksum);
  assert(!strncmp(checksum_str, inbuf + packetend + 1, 2));
  struct user_regs_struct regs;

  uint8_t tmpbuf[400];

  switch (request)
  {
  case 'c':
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&stat_loc);
    prepare_resume_reply(tmpbuf);
    write_packet(tmpbuf);
    break;
  case 'g':
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    for (int i = 0; i < sizeof(reg_map); i++)
      for (int j = 0; j < reg_size[i]; j++)
        snprintf(tmpbuf + 16 * i + 2 * j, 3, "%02x", ((uint8_t *)&regs)[reg_map[i] * 8 + j]);
    write_packet(tmpbuf);
    break;
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
      int i, j;
      for (i = 0; i < mlen; i += j)
      {
        mdata = ptrace(PTRACE_PEEKDATA, pid, maddr, NULL);
        for (j = 0; j < 8 && i + j < mlen; j++)
          snprintf(tmpbuf + (i + j) * 2, 3, "%02x", ((uint8_t *)&mdata)[j]);
        maddr += j;
      }
    }
    else
    {
      int i, j;
      for (i = 0; i < mlen; i += 8)
      {
        j = (mlen - i >= 8) ? 8 : (mlen - i);
        assert(8 == j);
        memcpy(tmpbuf, payload + i, j);
        mdata = strtoul(tmpbuf, NULL, 16);
        ptrace(PTRACE_POKEDATA, pid, maddr + i, mdata);
      }
    }
    write_packet(tmpbuf);
    break;
  }
  case 'p':
  {
    int i = strtol(payload, NULL, 16);
    if (i > sizeof(reg_map))
    {
      write_packet("E01");
      break;
    }
    size_t regdata = ptrace(PTRACE_PEEKUSER, pid, 8 * reg_map[i], NULL);
    for (int j = 0; j < reg_size[i]; j++)
      snprintf(tmpbuf + 2 * j, 3, "%02x", ((uint8_t *)&regdata)[j]);
    write_packet(tmpbuf);
    break;
  }
  case 'P':
  {
    int i = strtol(payload, &payload, 16);
    assert('=' == *payload++);
    if (i > sizeof(reg_map) && i != 57)
    {
      write_packet("E01");
      break;
    }
    size_t regdata;
    tmpbuf[2] = '\0';
    for (int j = 0; j < 8; j++)
    {
      strncpy(tmpbuf, payload + j * 2, 2);
      ((uint8_t *)&regdata)[j] = strtol(tmpbuf, NULL, 16);
    }
    if (i == 57)
      ptrace(PTRACE_POKEUSER, pid, 8 * ORIG_RAX, regdata);
    else
      ptrace(PTRACE_POKEUSER, pid, 8 * reg_map[i], regdata);
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
    maddr = strtoul(payload, &payload, 16);
    assert(',' == *payload++);
    mlen = strtoul(payload, &payload, 16);
    assert(':' == *payload++);
    assert(mlen <= 8);
    mdata = ptrace(PTRACE_PEEKDATA, pid, maddr, NULL);
    memcpy((void *)&mdata, payload, mlen);
    ptrace(PTRACE_POKEDATA, pid, maddr, mdata);
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

  memmove(inbuf, inbuf + packetend + 3, inbufpos - packetend);
  inbufpos -= packetend + 3;
}

void get_request(int sock_fd)
{
  while (1)
  {
    read_packet(sock_fd);
    process_packet();
    write_flush(sock_fd);
  }
}

void start_server()
{
  int ret;
  const int one = 1;
  int listen_fd, sock_fd;

  listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd < 0)
  {
    perror("socket() failed");
    exit(-1);
  }
  ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (ret < 0)
  {
    perror("setsockopt() failed");
    exit(-1);
  }
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(1234);
  ret = bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0)
  {
    perror("bind() failed");
    exit(-1);
  }
  ret = listen(listen_fd, 1);
  if (ret < 0)
  {
    perror("listen() failed");
    exit(-1);
  }

  sock_fd = accept(listen_fd, NULL, NULL);
  ret = setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  memset(inbuf, 0, sizeof(inbuf));
  inbufpos = 0;
  get_request(sock_fd);
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
    wait(&stat_loc);
    start_server();
  }
  return 0;
}