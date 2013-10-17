
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
#include "tcp.h"

/*
 * Сканирование функцией connect()
 * Аргументы:
 *    host - ip-адрес целевого сервера (уже в network byte order)
 *    res - массив, в который будут записаны результаты по
 *          сканированию каждого порта (каждый элемент данного массива
 *          содержит в себе результаты сканирований одного порта)
 */

int connectTest(const in_addr_t host,uint8_t* res)
{
	struct sockaddr_in addr;
	uint16_t port;
	socklen_t addrlen = sizeof(addr);

	/* Структура addr будет содержать IP-адрес и описывать способ
	 * доступа (AF_INET) к целевому серверу */
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = host;

	/* Создаем сокет для взаимодействия посредством сети (AF_INET),
	 * тип сокета - SOCK_STREAM («поточный» сокет),
	 * протокол - 0 (по умолчанию для SOCK_STREAM это TCP) */
	int sock = socket(AF_INET,SOCK_STREAM,0);

	if(sock == -1)
	{
		printError(ERROR_SOCKET_CREATE,__FILE__,__LINE__,NULL);
		return -1;
	}
	
	/* Просканировать каждый порт */
	for(port = 0; port < NUM_PORT; port++)
	{
		/* Номер целевого порта записывает в структуру addr в network byte order */
		addr.sin_port = htons(port + 1);

		/* Пытаемся подключится */
		if(!connect(sock,(struct sockaddr*)&addr,addrlen))
		{
			/* Подключится удалось */
			res[port] |= CONNECT_TEST_MASK;

			close(sock);

			sock = socket(AF_INET,SOCK_STREAM,0);
		}

		/* Небольшая пауза - для усложнения определения факта сканирования */
		usleep(INTERVAL);
	}

	/* Закрываем сокет */
	close(sock);

	return 0;
};

/*
 * Сканирования: SYN, FIN, Xmas Tree, NULL
 * Аргументы:
 *		mask - маска сканирования (уникальна для каждого типа сканирования)
 *		host - IP-адрес целевого сервера в network byte order
 *    res - массив, в который будут записаны результаты по
 *          сканированию каждого порта (каждый элемент данного массива
 *          содержит в себе результаты сканирований одного порта)
 */

int flagsTest(const uint8_t mask,const in_addr_t host,uint8_t* res)
{
	/* Проверка корректности указания типа сканирования */
	if(mask != SYN_TEST_MASK && mask != FIN_TEST_MASK
			&& mask != XMASTREE_TEST_MASK && mask != NULL_TEST_MASK)
	{
		printError(ERROR_BAD_FLAGS_TEST,__FILE__,__LINE__,(void*)&mask);
		return -1;
	}

	/* Создаем сырой TCP-сокет
	 * (сырой сокет требует прав суперпользователя (точнее CAP_NET_RAW), однако он - единственный
	 * способ получить доступ к заголовкам TCP и IP пакетов */
	int sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(sock < 0)
	{
		printError(ERROR_SOCKET_CREATE,__FILE__,__LINE__,NULL);
		return -1;
	}

	/* Делаем сокет неблокирующимся */
	if(fcntl(sock,F_SETFL,O_NONBLOCK) < 0)
	{
		printError(ERROR_SOCKET_SET_NONBLOCK,__FILE__,__LINE__,NULL);
		close(sock);
		return -1;
	}

	/* Формируем структуру dest - она будет содержать адрес целевого сервера и способ связи
	 * с ним (AF_INET) */
	struct sockaddr_in dest;
	socklen_t dest_len = sizeof(struct sockaddr_in);
	memset((void*)&dest,0,dest_len);
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = host;

	/* "Подключаемся" к целевому хосту - это позволит нам не формировать дополнительно
	 * IP-заголовок (без подключения нам бы пришлось это делать) */
	if(connect(sock,(struct sockaddr*) & dest,dest_len) < 0)
	{
		printError(ERROR_SOCKET_CONNECT,__FILE__,__LINE__,"flagsTest");
		close(sock);
		return -1;
	}
	
	/* Определим, какой IP-адрес имеет интерфейс, с которого мы отправляем пакеты */
	struct sockaddr_in our_addr;
	socklen_t our_addr_len = sizeof(struct sockaddr_in);
	if(getsockname(sock,(struct sockaddr*) &our_addr,&our_addr_len))
	{
		printError(ERROR_SRC_INDEFINITE,__FILE__,__LINE__,NULL);
		close(sock);
		return -1;
	}

	/* Побочная роль сокета - мьютекс между "серверным" и
	 * "клиентским" (отправляющим пакеты) процессами 
	 * (пока родительский процесс не будет готов принимать пакеты, сокет будет заблокирован) */
	if(lockf(sock,F_LOCK,0) < 0)
	{
		printError(ERROR_LOCK,__FILE__,__LINE__,NULL);
		close(sock);
		return 0;
	}

	/* Создаем дочерний процесс - он будет отправлять пакеты */
	int client_proc = fork();
	if(!client_proc)
	{
		/* Дочерний - отправляющий - процесс
		 * (при порождении дочернего процесса открытые файловые дескрипторы
		 * клонируются - таким образом, теперь два процесса - дочерний и
		 * родительский - будут разделять один и тот же неблокирующийся
		 * сокет) */

		/* Ждем, когда родительский процесс будет готов принимать ответы (ждем того момента, когда
		 * родительский процесс разблокирует сокет) */
		while(lockf(sock,F_TEST,0));

		/* Для подсчета контрольной суммы заведем отдельный буфер (csum_buf),
		 * поскольку в checksum TCP-пакета должен учитываться
		 * псевдо-заголовок из некоторых полей IP-заголовка */
		char cl_buf[BUF_SIZE],csum_buf[BUF_SIZE];
		memset((void*)cl_buf,0,BUF_SIZE);
		memset((void*)csum_buf,0,BUF_SIZE);

		/* Структура tcphdr указывает на заголовок пакета в выделенном под пакет буфере */
		struct tcphdr *cl_tcph,*csum_tcph;
		cl_tcph = (struct tcphdr*) cl_buf;
		csum_tcph = (struct tcphdr*) (csum_buf + 12);

		/* Порт отправителя */
		cl_tcph->source = htons(PROGRAM_PORT);
		/* Число для нумерации TCP-сегментов - выбираем произвольно */
		cl_tcph->seq = 0xAABBCCDD;
		/* Мы не отправляем ответный пакет (флаг ACK будет сброшен) => номер предыдущего
		 * пакета сбрасываем в ноль */
		cl_tcph->ack_seq = 0;
		/* Размер заголовка TCP-пакета в двойных словах */
		cl_tcph->doff = sizeof(struct tcphdr) / 4;
		/* Размер TCP-окна */
		cl_tcph->window = htons(32792);
		/* Не используется - флаг URG будет сброшен в ноль */
		cl_tcph->urg_ptr = 0;

		/* В зависимости от типа сканирования правильным образом выставляем TCP-флаги */
		cl_tcph->syn = cl_tcph->urg = cl_tcph->ack = cl_tcph->psh = cl_tcph->rst = cl_tcph->fin = 0;
		switch (mask)
		{
			case SYN_TEST_MASK:
				{
					cl_tcph->syn = 1;
					break;
				}
			case FIN_TEST_MASK:
				{
					cl_tcph->fin = 1;
					break;
				}
			case XMASTREE_TEST_MASK:
				{
					cl_tcph->fin = cl_tcph->psh = cl_tcph->urg = 1;
					break;
				}
		}

		/* Подготавливаем буфер для подсчета контрольной суммы
		 * (формируем в начале буфера псевдо-заголовок из полей IP-заголовка,
		 * после чего копируем в буфер содержимое TCP-пакета (в нашем случае
		 * этот пакет состоит только из TCP-заголовка) */
		*(uint32_t*)csum_buf = our_addr.sin_addr.s_addr;
		*(uint32_t*)(csum_buf + 4) = host;
		*(char*)(csum_buf + 8) = 0;
		/* Младший байт от IPPROTO_TCP */
		*(char*)(csum_buf + 9) = (char) IPPROTO_TCP;
		*(uint16_t*)(csum_buf + 10) = htons(sizeof(struct tcphdr));
		memcpy((void*)(csum_buf + 12),(void*)cl_tcph, sizeof(struct tcphdr));

		uint16_t port;
		for(port = 0; port < NUM_PORT; port++)
		{
			/* Очередной порт */
			dest.sin_port = htons(port + 1);
			cl_tcph->dest = csum_tcph->dest = dest.sin_port;

			/* Пересчитываем контрольную сумму */
			cl_tcph->check = checkSum((const uint16_t*)csum_buf, 12 + sizeof(struct tcphdr));

			/* Отправляем пакет */
			sendto(sock,cl_buf,sizeof(struct tcphdr),0,(struct sockaddr*) &dest,dest_len);

			/* Задержка во избежания разнообразных плохих вещей - обнаружения факта сканирования,
			 * падение сервера в следствие SYN-флуда при SYN-сканировании и т.п. */
			usleep(INTERVAL);
		}

		/* Закрываем дочерную копию дескриптора сокета */
		close(sock);

		exit(0);
	}
	else if (client_proc < 0)
	{
		printError(ERROR_FORK,__FILE__,__LINE__,NULL);
		close(sock);
		return 0;
	}

	/* Родительский процесс будет принимать ответные пакеты */

	int epoll_fd = epoll_create(1);
	if(epoll_fd < 0)
	{
		printError(ERROR_EPOLL_CREATE,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		close(sock);
		return 0;
	}

	struct epoll_event new_event,event;
	new_event.events = EPOLLIN | EPOLLPRI;

	/* С помощью epoll будем следить за появлением очередного пакета в сокете */
	if(epoll_ctl(epoll_fd,EPOLL_CTL_ADD,sock,&new_event))
	{
		printError(ERROR_EPOLL_CTL,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		close(sock);
		return 0;
	}

	uint16_t nbo_program_port = htons(PROGRAM_PORT);

	/* Организуем с помощью разделяемой памяти таймер */

	/* Получение IPC-ключа */
	key_t shm_key = ftok(".",'w');
	if(shm_key == -1)
	{
		printError(ERROR_FTOK,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		close(sock);
		return 0;
	}

	/* Выделяем память (1 байт) под таймер */
	int shm_id = shmget(shm_key,1,0666 | IPC_CREAT);
	if(shm_id < 0)
	{
		printError(ERROR_SHMGET,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		close(sock);
		return 0;
	}

	/* Получаем указатель на созданную область разделяемой памяти */
	char *flag = (char*) shmat(shm_id,NULL,0);
	if((int) flag == -1)
	{
		printError(ERROR_SHMAT,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		close(sock);
		return 0;
	}

	/* Пока флаг установлен, будем принимать пакеты */
	*flag = 1;

	/* Запустим процесс, реализующий таймер (необходим во избежания
	 * частых блокировок принимающего - родительского - процесса,
	 * возникающих из-за опроса функций времени или из-за засыпаний) */
	int timer_proc = fork();
	if(!timer_proc)
	{
		/* Дочерний процесс - таймер */

		/* Закрываем копию дескриптора сокета */
		close(sock);

		sleep(DURATION);
		*flag = 0;

		shmdt(flag);

		exit(0);
	}
	else if (timer_proc < 0)
	{
		printError(ERROR_FORK,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		close(sock);
		return 0;
	}

	char sv_buf[BUF_SIZE];
	memset((void*)sv_buf,0,BUF_SIZE);

	/* При приеме TCP-пакетов из RAW-сокета ОС записывает в принимающий
	 * буфер еще и IP-заголовок */
	struct iphdr *sv_iph;
	struct tcphdr *sv_tcph;
	sv_iph = (struct iphdr*) sv_buf;
	sv_tcph = (struct tcphdr*) (sv_buf + sizeof(struct iphdr));

	/* Разблокируем процесс, отправляющий пакеты */
	if(lockf(sock,F_ULOCK,0) < 0)
	{
		printError(ERROR_ULOCK,__FILE__,__LINE__,NULL);
		kill(client_proc,SIGINT);
		kill(timer_proc,SIGINT);
		close(sock);
		return 0;
	}

	/* Принимаем и анализируем пакеты */
	while(*flag)
		if(epoll_wait(epoll_fd,&event,1,5000) > 0)
		{
			if(read(sock,(void*)sv_buf,BUF_SIZE) > 0
					&& sv_iph->saddr == host && sv_iph->daddr == our_addr.sin_addr.s_addr
					&& sv_tcph->dest == nbo_program_port)
			{
				if
					(
						(mask == SYN_TEST_MASK && sv_tcph->syn && sv_tcph->ack
						 && !sv_tcph->urg && !sv_tcph->rst && !sv_tcph->psh && !sv_tcph->fin)
					|| 
						(mask != SYN_TEST_MASK && sv_tcph->rst)
					)
					res[ntohs(sv_tcph->source) - 1] |= mask;
			}
		}

	shmdt(flag);

	/* Чтобы корректно удалить область разделяемой памяти ждем, пока не завершиться процесс - таймер
	 * (т.е. пока он не сделает shmdt перед завершением)
	 * (разумеется, разделяемая область удаляется, когда все ее пользователи сделают shmdt,
	 * но мы подстрахуемся) */
	int wait_timer_proc,status;
	do
		wait_timer_proc = waitpid(timer_proc,&status,0);
	while (!WIFEXITED(status) && wait_timer_proc != -1);

	shmctl(shm_id,IPC_RMID,NULL);

	/* Инвертируем результаты для всех, кроме SYN, сканирований
	 * (для FIN, Xmas Tree и NULL сканирований признак открытого порта - отсутствие
	 * RST-пакета в ответ) */
	if(mask != SYN_TEST_MASK)
	{
		uint32_t port;
		for(port = 0; port < NUM_PORT; port++)
			res[port] ^= mask;
	}

	/* Закрываем сокет (к данному моменту все дочерние процессы, очевидно, завершаться =>
	 * закроют свои копии дескрипторов сокета) */
	close(sock);

	return 0;
};

