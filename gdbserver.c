#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

int reg_map[] = {10, 5, 11, 12, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16, 18, 17, 20, 23, 24, 25, 26};
int reg_size[] = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 4};
uint8_t inbuf[32768];
uint8_t outbuf[32768];
int inbufpos;
int outbufpos;
int pid;
int stat_loc;

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

void read_packet(int sock_fd)
{
  while (1)
  {
    read_data_once(sock_fd);
    if (memchr(inbuf, '#', inbufpos))
      break;
  }
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

  write_data_raw((uint8_t *)"+", 1);
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

void process_packet()
{
  uint8_t *p = (uint8_t *)memchr(inbuf, '#', inbufpos);
  int packetend = p - inbuf;
  assert(inbuf[0] == '+' && inbuf[1] == '$');
  char request = inbuf[2];
  char *payload = (char *)&inbuf[3];
  inbuf[packetend] = '\0';

  uint8_t checksum = 0;
  uint8_t checksum_str[3];
  for (int i = 2; i < packetend; i++)
    checksum += inbuf[i];
  snprintf(checksum_str, 3, "%02lx", checksum);
  assert(!strncmp(checksum_str, inbuf + packetend + 1, 2));
  struct user_regs_struct regs;

  unsigned long long maddr, mlen, mdata;
  uint8_t tmpbuf[400];
  int i, j;

  switch (request)
  {
  case 'g':
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    for (i = 0; i < 24; i++)
      for (j = 0; j < reg_size[i]; j++)
        snprintf(tmpbuf + 16 * i + 2 * j, 3, "%02x", ((uint8_t *)&regs)[reg_map[i] * 8 + j]);
    write_packet(tmpbuf);
    break;
  case 'H':
    write_packet("OK");
    break;
  case 'm':
    maddr = strtoul(payload, &payload, 16);
    assert(',' == *payload++);
    mlen = strtoul(payload, &payload, 16);
    assert('\0' == *payload);
    mdata = ptrace(PTRACE_PEEKDATA, pid, maddr, NULL);
    for (i = 0; i < mlen; i++)
      snprintf(tmpbuf + i * 2, 3, "%02x", ((uint8_t *)&mdata)[i]);
    write_packet(tmpbuf);
    break;
  case 'p':
    i = strtol(payload, NULL, 16);
    mdata = ptrace(PTRACE_PEEKUSER, pid, 8 * reg_map[i], NULL);
    for (j = 0; j < reg_size[i]; j++)
      snprintf(tmpbuf + 2 * j, 3, "%02x", ((uint8_t *)&mdata)[j]);
    write_packet(tmpbuf);
    break;
  case 'q':
    process_query(payload);
    break;
  case 's':
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    wait(&stat_loc);
    snprintf(tmpbuf, 4, "S%02d", WEXITSTATUS(stat_loc));
    write_packet(tmpbuf);
    break;
  case 'v':
    process_vpacket(payload);
    break;
  case '?':
    snprintf(tmpbuf, 4, "S%02d", WEXITSTATUS(stat_loc));
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
  int reuseaddr = 1;
  int listen_fd, sock_fd;

  listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd < 0)
  {
    perror("socket() failed");
    exit(-1);
  }
  ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                   sizeof(reuseaddr));
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