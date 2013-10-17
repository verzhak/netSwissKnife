
#ifndef ALL_H
#define ALL_H

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/* Версия программы */
#define VERSION "0.2"

/* Дата выхода */
#define DATE "14.08.2009"

/* Количество сканируемых портов */
uint16_t NUM_PORT;

/* Флаг, предписывающий выводить (1) или не выводить (0) дополнительную информацию */
unsigned char VERBOSE;

/* Предписывает делать (1) или не делать (0) connect-тест при сканировании TCP-портов
 * (как показала практика, connect-тест очень медленный) */
unsigned char CONNECT_TCP_TEST_ENABLE;

/* Предписывать сканировать один (1) или все (0) IP-адреса данного хоста
 * (пригодится, если в программу передан символьный адрес, которому с
 * помощью DNS-сервисов ставится в соответствие несколько IP-адресов) */
unsigned char ONLY_FIRST_ADDRESS_SCAN;

/* Порт, на который будем ожидать пакеты - ответы */
#define PROGRAM_PORT 56789

/* Длительность принятия ответных пакетов (в секундах) */
uint8_t DURATION;

/* Длительность паузы между попытками подключения (в connectTest) или отправкой пакетов (в flagsTest)
 * (в миллисекундах) */
#define INTERVAL 1000

/* Порт для ping целевого хоста */
#define PORT_TO_PING 12345

/* id первого в цепочке ICMP-ECHO-пакетов */
#define FIRST_ECHO_ID 0xAAB0

/* Количество отправляемых ICMP-ECHO-пакетов при ping'е */
#define NUM_PING_PACKAGES 7

/* Ограничение на максимальное количество принятых пакетов при ожидании ICMP-ECHOREPLY-пакетов */
#define MAX_PACKAGES 17

/* Размер буфера под отправляемые пакеты */
#define BUF_SIZE 4096

/* Сахарная строка для красивого вывода */
#define SUGAR_STRING "#########################################################"

/* ############################################################################ */

uint16_t checkSum(const uint16_t *buf, uint16_t buf_size);

#endif

