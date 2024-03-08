#include <stdio.h>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "detours.h"

#pragma comment(lib, "Ws2_32.lib")

// Define Proxy IP and Port.
// Define Username & Password.
const char* _username = "username";
const char* _password = "password";
const char* _proxyIP = "127.0.0.1";
const int _proxyPort = 6969;

// Define Original Functions to Hook.
int (WSAAPI* realWSAConnect)(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) = WSAConnect;
int (WSAAPI* realConnect)(SOCKET s, const struct sockaddr* name, int namelen) = connect;

// SOCKS4 Protocol
int SOCKS4Protocol(SOCKET s, const struct sockaddr_in* dest)
{
	char buffer[256];
	buffer[0] = 0x04; // Version
	buffer[1] = 0x01; // Connect request
	buffer[2] = (dest->sin_port >> 0) & 0xFF;
	buffer[3] = (dest->sin_port >> 8) & 0xFF;
	buffer[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
	buffer[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
	buffer[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
	buffer[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
	sprintf_s( &buffer[ 8 ], 256 - 8, "%s", _username ); // Username
	send(s, buffer, 8 + strlen(_username), 0);

	recv(s, buffer, 8, 0);
	if (buffer[1] != 0x5A) // Request denied. 0x5A (90) indicates success.
	{
		return -1;
	}

	return 0;
}

// SOCKS5 Protocol
int SOCKS5Protocol(SOCKET s, const struct sockaddr_in* dest)
{
	char buffer[256];
	buffer[0] = 0x05; // Version
	buffer[1] = 0x01; // No. methods.
	buffer[2] = 0x02; // User & Pass auth.
	send(s, buffer, 3, 0);

	char handshakeBuffer[256];
	while (true){
		if (recv(s, handshakeBuffer, 256, 0) > 0)
		{
			if (handshakeBuffer[1] != 0x02) // Client has rejected our auth method of choice.
			{
				return -1;
			}

			break;
		}
	}

	buffer[0] = 0x01;
	buffer[1] = strlen(_username); // Username length
	sprintf_s(&buffer[2], 256 - 2, "%s", _username); // Username
	buffer[buffer[1] + 2] = strlen(_password); // Password length
	sprintf_s(&buffer[2 + buffer[1] + 1], 256 - 2 - buffer[1] - 1, "%s", _password) // Password
	send(s, buffer, 3 + strlen(_username) + strlen(_password), 0);

	while (true)
	{
		if (recv(s, handshakeBuffer, 256, 0) > 0)
		{
			if (handshakeBuffer[1] != 0x00) // Invalid username or password
			{
				return -1;
			}

			break;
		}
	}

	buffer[0] = 0x05; // version
	buffer[1] = 0x01; // TCP/IP
	buffer[2] = 0x00; // must be 0x00 always
	buffer[3] = 0x01; // IPv4 
	buffer[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
	buffer[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
	buffer[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
	buffer[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
	buffer[8] = (dest->sin_port >> 0) & 0xFF;
	buffer[9] = (dest->sin_port >> 8) & 0xFF;
	send(s, buffer, 10, 0);

	while (true)
	{
		if (recv(s, handshakeBuffer, 256, 0) > 0)
		{
			if (buffer[0] == 0x00) // Request successful
			{
				return 0;
			}
			
			return -1;
		}
	}
}

// Detour Function (WSAConnect).
int WSAAPI proxyWSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
{
	// Ignore IPv6.
	if (name->sa_family == AF_INET6)
	{
		//printf("IPv6 detected. Re-routing back through direct connection.\n\n");

		return realWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	}

	// Get Original Packet information.
	const struct sockaddr_in* destination = (struct sockaddr_in*)name;

	// Ignore loopback calls.
	if (destination->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
	{
		//printf("Loopback (IP: %s:%ld) detected. Re-routing back through direct connection.\n\n", inet_ntoa(destination->sin_addr), htons(destination->sin_port));

		return realWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	}

	// Define New (Proxy) IP Address & Port.
	struct sockaddr_in proxy;
	proxy.sin_family = AF_INET;
	proxy.sin_addr.s_addr = inet_addr(_proxyIP);
	proxy.sin_port = htons(_proxyPort);

	u_long noBlock = 1;
	int noDelay = 1;

	// Set Socket to be Non-Blocking.
	ioctlsocket(s, FIONBIO, &noBlock);

	// Set TCP_NODELAY to TRUE on the Socket.
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay));

	realConnect(s, (const struct sockaddr*)&proxy, sizeof(proxy));

	//printf("Attempting SOCKS4/5 authentication..\n");

	int index = 0;
	while (true)
	{
		if (index == 2) // 3 Attempts.
		{
			//printf("Authentication failed.\n");

			return realWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS); // Return to orig. call
		}

		// SOCKS5
		if (SOCKS5protocol == 0)
		{
			break;
		}

		// SOCKS4
		// if (SOCKS4protocol == 0)
		// {
		// 	break;
		// }

		index++;
	}

	//printf("Authentication successful. Proxification tunnel opened to %s:%ld\n\n", inet_ntoa(destination->sin_addr), htons(destination->sin_port));

	return 0;
}

//Detour Function (connect).
int WSAAPI proxyConnect(SOCKET s, const struct sockaddr* name, int namelen)
{
	// Ignore IPv6.
	if (name->sa_family == AF_INET6)
	{
		//printf("IPv6 detected. Re-routing back through direct connection.\n\n");

		return realConnect(s, name, namelen);
	}
	
	// Get Original Packet information.
	const struct sockaddr_in* destination = (struct sockaddr_in*)name;

	// Ignore loopback calls.
	if (destination->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
	{
		//printf("Loopback (IP: %s:%ld) detected. Re-routing back through direct connection.\n\n", inet_ntoa(destination->sin_addr), htons(destination->sin_port));

		return realConnect(s, name, namelen);
	}

	// Define New (Proxy) IP Address & Port.
	struct sockaddr_in proxy;
	proxy.sin_family = AF_INET;
	proxy.sin_addr.s_addr = inet_addr(_proxyIP);
	proxy.sin_port = htons(_proxyPort);

	u_long noBlock = 1;
	int noDelay = 1;

	//Set Socket to be Non-Blocking.
	ioctlsocket(s, FIONBIO, &noBlock);

	// Set TCP_NODELAY to TRUE on the Socket.
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay));

	realConnect(s, (const struct sockaddr*)&proxy, sizeof(proxy));

	//printf("Attempting SOCKS4/5 authentication..\n");

	int index = 0;
	while (true)
	{
		if (index == 2) // 3 Attempts.
		{
			//printf("Authentication failed.\n");

			return realWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS); // Return to orig. call
		}

		// SOCKS5
		if (SOCKS5protocol == 0)
		{
			break;
		}

		// SOCKS4
		// if (SOCKS4protocol == 0)
		// {
		// 	break;
		// }

		index++;
	}

	//printf("Authentication successful. Proxification tunnel opened to %s:%ld\n\n", inet_ntoa(destination->sin_addr), htons(destination->sin_port));

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	//AllocConsole();
	//AttachConsole(GetCurrentProcessId());
	//freopen("CON", "w", stdout);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)realWSAConnect, proxyWSAConnect);
	DetourAttach(&(PVOID&)realConnect, proxyConnect);
	DetourTransactionCommit();

	//if (DetourTransactionCommit() == NO_ERROR)
	//{
	//	printf("Hooks installed.\n\n");
	//}

	//else
	//{
	//	printf("Failed to install hooks.\n\n");
	//}

	return TRUE;
}
