#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

uint8_t inbuf[32768];
uint8_t outbuf[32768];
int inbufpos;
int outbufpos;

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
    write_packet("PacketSize=32768");
  if (!strcmp(name, "TStatus"))
    write_packet("");
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

  unsigned int maddr, mlen;
  switch (request)
  {
  case 'g':
    write_packet("00000000000000000000000000000000000000000000000000000000000000000000000000000000");
    break;
  case 'H':
    write_packet("OK");
    break;
  case 'm':
    maddr = strtoul(payload, &payload, 16);
    assert(',' == *payload++);
    mlen = strtoul(payload, &payload, 16);
    assert('\0' == *payload);
    write_packet("aa");
    break;
  case 'q':
    process_query(payload);
    break;
  case 'v':
    process_vpacket(payload);
    break;
  case '?':
    write_packet("S05");
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

int main()
{
  start_server();
  return 0;
}