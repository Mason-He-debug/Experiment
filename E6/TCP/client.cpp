// Client.cpp : Defines the entry point for the console application.
#include "winsock2.h"
#include <WS2tcpip.h>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;

int main(int argc, char* argv[])
{
	const int BUF_SIZE = 64;
	WSADATA			wsd;				//WSADATA����
	SOCKET			sClient;			//�ͻ����׽���
	SOCKADDR_IN		servAddr;			//��������ַ
	char			bufSend[BUF_SIZE];	//�������ݻ�����
	char			bufRecv[BUF_SIZE];  //�������ݻ�����
	int				retVal;				//����ֵ
	const char*			closeSymbol = "0";//����ͨ�ŵı�־

	// ���÷���˵�ַ
	servAddr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", (void*)&servAddr.sin_addr.S_un.S_addr);
	servAddr.sin_port = htons((short)50001);
	int	nServAddlen = sizeof(servAddr);

	// ��ʼ���׽��ֶ�̬��
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		cout << "WSAStartup failed!" << endl;
		return -1;
	}

	// ����������׽���
	sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sClient)
	{
		cout << "Socket failed !" << endl;
		WSACleanup();               //�ͷ��׽�����Դ
		return  -1;
	}
	else
	{
		cout << "Client Socket init !" << endl;
	}

	// �ͻ���socket���ӷ����
	retVal = connect(sClient, (LPSOCKADDR)&servAddr, sizeof(servAddr));
	if (SOCKET_ERROR == retVal)
	{
		cout << "connect failed!" << endl;
		closesocket(sClient);	//�ر��׽���
		WSACleanup();			//�ͷ��׽�����Դ
		return -1;
	}
	else
	{
		cout << "Two Sockets are ready for communication !" << endl;
	}

	// ѭ���ȴ��������˷������� & �ӷ���˽�������
	while (true) {
		// ��ʼ��buf�ռ�
		ZeroMemory(bufSend, BUF_SIZE);

		// �����˷�������buf
		cout << "Data send to Server Socket: ";
		gets_s(bufSend);
		retVal = send(sClient, bufSend, strlen(bufSend), 0);
		if (SOCKET_ERROR == retVal)
		{
			cout << "send failed!" << endl;
			closesocket(sClient);	//�رշ�����׽���
			WSACleanup();		    //�ͷ��׽�����Դ
			return -1;
		}
		// ���ͻ��˷��͵�������'0'�����ʾ�ͻ���������˴�TCPͨ��
		if (!strcmp(bufSend, closeSymbol))
		{
			cout << "Client Socket wants to finish this communication" << endl;
			break;
		}

		// �ӷ���˽�������bufRecv
		retVal = recv(sClient, bufRecv, BUF_SIZE, 0);
		bufRecv[retVal] = '\0';
		cout << "Data recv from Server Socket: " << bufRecv << endl;
		// ������˷��͵�������'0'�����ʾ�����������˴�TCPͨ��		
		if (!strcmp(bufRecv, closeSymbol))
			//if (bufRecv[0] == '0')
		{
			cout << "Server Socket wants to finish this communication" << endl;
			break;
		}

	}
	//�˳�
	closesocket(sClient);	//�رշ�����׽���
	WSACleanup();
	//�ͷ��׽�����Դ
	Sleep(5000);
	return 0;
}