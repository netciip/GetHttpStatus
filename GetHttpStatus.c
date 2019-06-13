#include <stdio.h>
#include <windows.h>
#include <Shlwapi.h>
#include <WinInet.h>


#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Wininet.lib")


DWORD GetHttpStatusCode(CHAR *ServerName, WORD ServerPort, CHAR *Url)
{
  if (ServerName == NULL || ServerPort <= 0 || ServerPort > 65535 || Url == NULL)
  {
    return 0;
  }


  CHAR HostName[MAX_PATH] = { 0 };
  CHAR UrlPath[2048] = { 0 };
  URL_COMPONENTSA UrlComponents = { 0 };
  UrlComponents.dwStructSize = sizeof(UrlComponents);
  UrlComponents.lpszHostName = HostName;
  UrlComponents.dwHostNameLength = ARRAYSIZE(HostName);
  UrlComponents.lpszUrlPath = UrlPath;
  UrlComponents.dwUrlPathLength = ARRAYSIZE(UrlPath);
  if (InternetCrackUrlA(Url, strlen(Url), 0, &UrlComponents) == FALSE)
  {
    return 0;
  }


  DWORD HttpStatusCode = 0;
  HINTERNET hHttpOpenRequest = NULL;
  HINTERNET hInternetConnect = NULL;
  HINTERNET hInternetOpen    = NULL;
  hInternetOpen = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
  if (NULL == hInternetOpen)
  {
    goto Exit;
  }


  hInternetConnect = InternetConnectA(hInternetOpen, ServerName, ServerPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
  if (NULL == hInternetConnect)
  {
    goto Exit;
  }


  DWORD Flags = INTERNET_FLAG_NO_AUTO_REDIRECT;
  if (UrlComponents.nScheme == INTERNET_SCHEME_HTTPS)
  {
    Flags |= INTERNET_FLAG_SECURE;
    Flags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
    Flags |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    Flags |= INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP;
    Flags |= INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS;
  }
  hHttpOpenRequest = HttpOpenRequestA(hInternetConnect, "GET", UrlComponents.lpszUrlPath, NULL, NULL, NULL, Flags, 0);
  if (NULL == hHttpOpenRequest)
  {
    goto Exit;
  }


  if (UrlComponents.nScheme == INTERNET_SCHEME_HTTPS)
  {
    DWORD Option = 0;
    Option |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    Option |= SECURITY_FLAG_IGNORE_REVOCATION;
    Option |= SECURITY_FLAG_IGNORE_WRONG_USAGE;
    if (InternetSetOptionA(hHttpOpenRequest, INTERNET_OPTION_SECURITY_FLAGS, &Option, sizeof(Option)) == FALSE)
    {
      goto Exit;
    }
  }


  CHAR HeaderHost[600] = { 0 };
  strcat_s(HeaderHost, 600, "Host: ");
  strcat_s(HeaderHost, 600, UrlComponents.lpszHostName);
  strcat_s(HeaderHost, 600, "\r\n");
  if (HttpAddRequestHeadersA(hHttpOpenRequest, HeaderHost, strlen(HeaderHost), HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE) == FALSE)
  {
    goto Exit;
  }


  if (HttpSendRequestA(hHttpOpenRequest, NULL, 0, NULL, 0) == FALSE)
  {
    goto Exit;
  }

  
  DWORD Buffer = 0;
  DWORD BufferLength = sizeof(Buffer);
  if (HttpQueryInfoA(hHttpOpenRequest, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &Buffer, &BufferLength, NULL) == FALSE)
  {
    goto Exit;
  }
  HttpStatusCode = Buffer;


Exit:
  InternetCloseHandle(hHttpOpenRequest);
  InternetCloseHandle(hInternetConnect);
  InternetCloseHandle(hInternetOpen);
  return HttpStatusCode;
}


int main(int argc, char *argv[])
{
  if (argc != 3 || strcmp(PathFindExtensionA(argv[1]), ".txt") != 0 || !PathFileExistsA(argv[1]) || !PathIsURLA(argv[2]))
  {
    printf_s("Usage:\n\t%s <TargetList.txt> <Url>\n\t%s X:\\Target.txt http[s]://example.com/\n",
      PathFindFileNameA(argv[0]), PathFindFileNameA(argv[0]));
    return 0;
  }


  DWORD Count = 0;
  DWORD Count2 = 0;
  DWORD Count3 = 0;
  FILE *stream = NULL;
  errno_t err = fopen_s(&stream, argv[1], "r");
  if (err == 0)
  {
    CHAR Line[MAX_PATH] = { 0 };
    while (fscanf_s(stream, "%s", Line, _countof(Line)) > 0)
    {
      Count3++;
    }

    fseek(stream, 0L, SEEK_SET);
    while (fscanf_s(stream, "%s", Line, _countof(Line)) > 0)
    {
      CHAR Url[2048] = { 0 };
      strcat_s(Url, _countof(Url), "http://");
      strcat_s(Url, _countof(Url), Line);

      CHAR HostName[MAX_PATH] = { 0 };
      URL_COMPONENTSA Target = { 0 };
      Target.dwStructSize = sizeof(Target);
      Target.lpszHostName = HostName;
      Target.dwHostNameLength = ARRAYSIZE(HostName);
      if (InternetCrackUrlA(Url, strlen(Url), 0, &Target))
      {
        strcpy_s(Url, _countof(Url), argv[2]);
        DWORD HttpStatusCode = GetHttpStatusCode(Target.lpszHostName, Target.nPort, Url);
        if (HttpStatusCode != 0 && HttpStatusCode != 400)
        {
          Count++;
          printf_s("\r[%d] %s:%d  %d  %s\n", Count, Target.lpszHostName, Target.nPort, HttpStatusCode, Url);
        }

        Count2++;
        printf_s("\r %d/%d", Count2, Count3);
      }
    }
    fclose(stream);
  }

  return 0;
}
