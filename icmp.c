
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include "error.h"
#include "all.h"
#include "icmp.h"

/* 
 * Определение состояния сервера с помощью ECHO-пакетов
 * Аргументы:
 *		host - IP-адрес целевого сервера в network byte order
 * Возращаемое значение: число принятых ECHO_REPLY-пакетов
 */

uint8_t ping_icmp(const in_addr_t host)
{
	in_addr_t our_addr = 0;

	/* Создаем icmp-сокет (данный сокет должен быть сырым) */
	int sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(sock == -1)
	{
		printError(ERROR_SOCKET_CREATE,__FILE__,__LINE__,NULL);
		return 0;
	}

	/* Делаем сокет неблокирующимся */
	if(fcntl(sock,F_SETFL,O_NONBLOCK) < 0)
	{
		printError(ERROR_SOCKET_SET_NONBLOCK,__FILE__,__LINE__,NULL);
		close(sock);
		return 0;
	}

	/* Блокируем сокет (сокет будет играть побочную роль мьютекса) */
	if(lockf(sock,F_LOCK,0) < 0)
	{
		printError(ERROR_LOCK,__FILE__,__LINE__,NULL);
		close(sock);
		return 0;
	}

	/* Дочерний процесс будет посылать ECHO-пакеты ("клиент") */
	int client_proc = fork();
	if(!client_proc)
	{
		/* Ждем, когда родительский процесс подготовится к принятию ECHO-REPLY-пакетов
		 * (то есть ждем, пока родительский процесс не разблокирует сокет) */
		while(lockf(sock,F_TEST,0));

		/* Подготавливаем буфер (cl_buf) для содержимого пакетов и указатель (cl)
		 * для редактирования заголовка ICMP-пакета в данном буфере */
		char cl_buf[BUF_SIZE];
		struct icmphdr* cl = (struct icmphdr*) cl_buf;
		size_t cl_size = sizeof(struct icmphdr);
		memset((void*)cl_buf,0,BUF_SIZE);

		/* Структура dest содержит адрес целевого сервера и тип взаимодействия (AF_INET) */
		struct sockaddr_in dest;
		socklen_t dest_len = sizeof(struct sockaddr_in);
		memset((void*)&dest,0,dest_len);
		dest.sin_family = AF_INET;
		dest.sin_port = PORT_TO_PING;
		dest.sin_addr.s_addr = host;

		/* Подготовка заголовка icmp-пакета */
		/* Тип сообщения - ECHO */
		cl->type = ICMP_ECHO;
		/* Код сообщения - не используется */
		cl->code = 0;
		/* Наши пакеты не ECHO_REPLY, поэтому поле sequence обнуляем */
		cl->un.echo.sequence = 0;
	
		/* Посылаем NUM_PING_PACKAGES пакетов с id начиная с FIRST_ECHO_ID */
		unsigned int last_1_echo_id = FIRST_ECHO_ID + NUM_PING_PACKAGES;
		for(cl->un.echo.id = FIRST_ECHO_ID; cl->un.echo.id < last_1_echo_id; cl->un.echo.id++)
		{
			/* Контрольную сумму нужно пересчитывать с новым значением
			 * id, но с полем контрольной суммы, сброшенным в 0 */
			cl->checksum = 0;
			cl->checksum = checkSum((uint16_t*)cl,sizeof(struct icmphdr));

			/* Отправляем пакет */
			sendto(sock,(void*)cl_buf,cl_size,0,(struct sockaddr*)&dest,dest_len);

			/* Задержка */
			usleep(INTERVAL);
		}

		/* Закрываем дочерную копию дескриптора сокета */
		close(sock);

		/* Завершаем дочерний процесс */
		exit(0);
	}
	else if (client_proc < 0)
	{
		printError(ERROR_FORK,__FILE__,__LINE__,NULL);
		return 0;
	}

	/* Родительский процесс будет принимать ECHO-REPLY-пакеты */

	/* Подготавливаем буфер для поступающих пакетов (sv_buf) и указатели на IP и ICMP
	 * заголовки в данном буфере (sv_iph и sv_icmph) */
	char sv_buf[BUF_SIZE];
	struct iphdr* sv_iph = (struct iphdr*) sv_buf;
	struct icmphdr* sv_icmph = (struct icmphdr*) (sv_buf + sizeof(struct iphdr));
	memset((void*)sv_buf,0,BUF_SIZE);

	int epoll_fd = epoll_create(1);
	if(epoll_fd < 0)
	{
		printError(ERROR_EPOLL_CREATE,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		return 0;
	}

	struct epoll_event new_event,event;
	new_event.events = EPOLLIN | EPOLLPRI;

	/* С помощью epoll будем ждать прихода сообщений в сокет */
	if(epoll_ctl(epoll_fd,EPOLL_CTL_ADD,sock,&new_event))
	{
		printError(ERROR_EPOLL_CTL,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		return 0;
	}

	unsigned char is_wait = 1;
	unsigned char max_packages = MAX_PACKAGES;
	uint8_t return_packages = 0;

	/* Команда "старт" для дочернего процесса - теперь он отправляет ECHO-пакеты на целевой хост */
	if(lockf(sock,F_ULOCK,0) < 0)
	{
		printError(ERROR_ULOCK,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		return 0;
	}

	/* Проверяем сокет на пакеты, пока не истекло время ожидания очередного
	 * пакеты; пока не обработано максимальное количество пакетов (на случай,
	 * если мы параллельно пингуем кого-то еще) и пока не пришли ECHO-REPLY-пакеты
	 * на все посланные ECHO-пакеты
	 * (select с более удобным таймером не работает в данном случае) */
	while(is_wait && max_packages && return_packages != NUM_PING_PACKAGES)
		if(epoll_wait(epoll_fd,&event,1,5000) > 0)
		{
			max_packages--;
			if(read(sock,(void*)sv_buf,BUF_SIZE) > 0
				&& sv_icmph->type == ICMP_ECHOREPLY && sv_icmph->un.echo.id - FIRST_ECHO_ID < NUM_PING_PACKAGES)
			{
				return_packages++;

				if(!our_addr)
					our_addr = sv_iph->daddr;
			}
		}
		else
			/* Прошло максимальное время ожидания */
			is_wait = 0;

	/* Закрываем сокет (дочерний процесс со своей копией дескриптора уже давно
	 * закрыл копию и завершился) */
	close(sock);

	return return_packages;
}

