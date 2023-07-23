#include "../Header/RabbitAdventure.h"
#include <io.h>     //_access
#include <direct.h> //_mkdir
#include <conio.h>
#include <process.h> //_beginthreadex
#include <optional>
#include <filesystem>  //std::filesystem::path
#include <functional>
#pragma comment(lib,"../../Lib/DdddOcr/DdddOcr.lib")

using namespace cv;

extern "C"
{
	__declspec(dllimport) void Init();
	__declspec(dllimport) char* Classification(char* base64Img);
	__declspec(dllimport) void Close();
}

char* WCharToChar(const WCHAR* lpszSrc, char* lpszDes, DWORD nBufLen)
{
	size_t reultLen;
	if (lpszSrc == NULL || lpszSrc[0] == '\0' || lpszDes == NULL || nBufLen < 1)
	{
		return NULL;
	}
	::memset(lpszDes, 0, sizeof(char) * nBufLen);
	// trans-code ignore locale setting
	reultLen = ::WideCharToMultiByte(CP_ACP, NULL, lpszSrc, -1, lpszDes, nBufLen - 1, NULL, NULL);
	if (reultLen <= 0)
	{
		return NULL;
	}
	return lpszDes;
}

WCHAR* CharToWChar(const char* lpszSrc, WCHAR* lpszDes, DWORD nBufLen)
{
	size_t reultLen;
	if (lpszSrc == NULL || lpszSrc[0] == '\0' || lpszDes == NULL || nBufLen < 1)
	{
		return NULL;
	}
	memset(lpszDes, 0, sizeof(WCHAR) * nBufLen);
	// trans-code ignore locale setting
	reultLen = ::MultiByteToWideChar(CP_ACP, NULL, lpszSrc, -1, lpszDes, nBufLen - 1);
	if (reultLen <= 0)
	{
		return NULL;
	}
	return lpszDes;
}

std::string exePathGet()//处理了中文
{
	std::string re = "";
	TCHAR exeFullPath[MAX_PATH];
	GetModuleFileNameW(NULL, exeFullPath, MAX_PATH);
	std::wstring strPath = (std::wstring)exeFullPath;
#pragma warning(disable:4267)
	int pos = strPath.find_last_of('\\', (size_t)strPath.length());
#pragma warning(default:4267)
	//返回除了运行exe文件外的文件路径
	std::wstring wExePath = strPath.substr(0, pos);
	char* pBuffer = (char*)malloc(sizeof(char) * MAX_PATH);
	_ASSERT(pBuffer != NULL);
	::memset(pBuffer, 0, sizeof(char) * MAX_PATH);
	if (NULL != WCharToChar(wExePath.c_str(), pBuffer, sizeof(char) * MAX_PATH))
	{
		re = std::string(pBuffer);
	}
	::free(pBuffer);
	pBuffer = NULL;
	return re;
}

std::string exePath = exePathGet();

unsigned __stdcall startUping(void* p)
{
	Scrcpy* obj = (Scrcpy*)p;
	_ASSERT(NULL != obj);

	DWORD dwRet = 0u;
	SECURITY_ATTRIBUTES   sa;
	bool findAdbDevice = false;
	TCHAR Ttcommand[512] = { 0 };

	std::string funKey = "";
#pragma region scrcpy配置
	//使用uuid
	funKey += " -s " + obj->uuid;
	if (obj->bStayAwak)
	{
		funKey += " -w";
	}
	if (obj->bScreenOff)
	{
		funKey += " -S";
	}
	if (obj->bFpsPrint)
	{
		funKey += " --print-fps";
	}
	if (obj->bTopAlways)
	{
		funKey += " --always-on-top";
	}
	if (obj->bScreenOffIfExit)
	{
		funKey += " --power-off-on-close";
	}
	if (obj->bBorderLess)
	{
		funKey += " --window-borderless";
	}
	if (obj->bPositionX)
	{
		funKey += " --window-x=" + std::to_string(obj->positionX);
	}
	if (obj->bPositionY)
	{
		funKey += " --window-y=" + std::to_string(obj->positionY);
	}
	if (obj->bWidth)
	{
		funKey += " --window-width=" + std::to_string(obj->scrcpyW);
	}
	if (obj->bHeight)
	{
		funKey += " --window-height=" + std::to_string(obj->scrcpyH);
	}
#pragma endregion
	//第一次调用返回转换后的字符串长度，用于确认为wchar_t*开辟多大的内存空间
	int pSize = MultiByteToWideChar(CP_OEMCP, 0, funKey.c_str(), (int)funKey.length() + 1, NULL, 0);
	wchar_t* pWCStrKey = new wchar_t[pSize];
	//第二次调用将单字节字符串转换成双字节字符串
	MultiByteToWideChar(CP_OEMCP, 0, funKey.c_str(), (int)funKey.length() + 1, pWCStrKey, pSize);
	swprintf_s(Ttcommand, 512, L"scrcpy.exe %s ", pWCStrKey);
	std::wcout << Ttcommand << std::endl;
	delete[]pWCStrKey;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&obj->hRead, &obj->hWrite, &sa, 0))
	{
		wprintf(L"%s,,CreatePipe fail.\n", Ttcommand);
		return -1;
	}
	obj->si.cb = sizeof(STARTUPINFO);
	GetStartupInfoW(&obj->si);
	obj->si.hStdError = obj->hWrite;
	obj->si.hStdOutput = obj->hWrite;
	obj->si.wShowWindow = SW_HIDE;
	obj->si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	TCHAR Ttdir[512] = { 0 };
	//第一次调用返回转换后的字符串长度，用于确认为wchar_t*开辟多大的内存空间
	pSize = MultiByteToWideChar(CP_OEMCP, 0, exePath.c_str(), (int)exePath.length() + 1, NULL, 0);
	wchar_t* pWCStrDir = new wchar_t[pSize];
	MultiByteToWideChar(CP_OEMCP, 0, exePath.c_str(), (int)exePath.length() + 1, pWCStrDir, pSize);
	if (!::CreateProcessW(NULL, Ttcommand, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, pWCStrDir, &obj->si, obj->pi))
	{
		delete[]pWCStrDir;
		pWCStrDir = NULL;
		wprintf(L"%s,CreateProcess fail.\n", Ttcommand);
		return -1;
	}
	delete[]pWCStrDir;
	pWCStrDir = NULL;
	ResumeThread(obj->pi->hThread);

	char buffer[4096] = { 0 };
	DWORD nBytesToRead = 0;
	int doCnt = 40;
	std::string oneRe;
	while (true)
	{
		::memset(buffer, 0, sizeof(char) * 4096);
		//偷窥一下管道里是否有数据
		if (!PeekNamedPipe(obj->hRead, buffer, 4095, &nBytesToRead, 0, 0))
		{
			break;
		}
		if (nBytesToRead <= 0)
		{
			doCnt--;
			if (doCnt <= 0)
			{
				break;
			}
			Sleep(500);
			continue;
		}
		DWORD pDwRead = 0;
		::memset(buffer, 0, sizeof(char) * 4096);
		if (ReadFile(obj->hRead, buffer, nBytesToRead, &pDwRead, NULL))
		{
			oneRe += buffer;
			if (std::string::npos != oneRe.find("INFO: ") && std::string::npos != oneRe.find("fps")) //认为开始打印fps值就是程序启动成功了
			{
				obj->bStartUp = true;
				//printf("fps cout enter,while exit.\n");
				//break;
			}
		}
		Sleep(1000);
	}//while
	printf("\n\n\n startUping done!!!!!!!!!!!!!!!!!!!!\n\n\n");
	return 0;
}

Ctl::Ctl()
{

}

int Ctl::AdbCmd(const std::string adbInput, const std::string matchOut, const std::string sign, bool debug)
{
	PROCESS_INFORMATION pi;
	HANDLE   hRead, hWrite;
	STARTUPINFO   si;

	DWORD dwRet = 0u;
	SECURITY_ATTRIBUTES   sa;
	bool findAdbDevice = false;
	TCHAR Ttcommand[512] = { 0 };

	//第一次调用返回转换后的字符串长度，用于确认为wchar_t*开辟多大的内存空间
	int pSize = MultiByteToWideChar(CP_OEMCP, 0, adbInput.c_str(), (int)adbInput.size() + 1, NULL, 0);
	wchar_t* pWCStrKey = new wchar_t[pSize];
	//第二次调用将单字节字符串转换成双字节字符串
	MultiByteToWideChar(CP_OEMCP, 0, adbInput.c_str(), (int)adbInput.size() + 1, pWCStrKey, pSize);
	swprintf_s(Ttcommand, 512, L"adb.exe %s ", pWCStrKey);
	std::wcout << Ttcommand << std::endl;
	delete[]pWCStrKey;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		wprintf(L"%s,,CreatePipe fail.\n", Ttcommand);
		return -1;
	}
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfoW(&si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	TCHAR Ttdir[512] = { 0 };
	//第一次调用返回转换后的字符串长度，用于确认为wchar_t*开辟多大的内存空间
	pSize = MultiByteToWideChar(CP_OEMCP, 0, exePath.c_str(), (int)exePath.length() + 1, NULL, 0);
	wchar_t* pWCStrDir = new wchar_t[pSize];
	MultiByteToWideChar(CP_OEMCP, 0, exePath.c_str(), (int)exePath.length() + 1, pWCStrDir, pSize);
	if (!::CreateProcessW(NULL, Ttcommand, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, pWCStrDir, &si, &pi))
	{
		delete[]pWCStrDir;
		pWCStrDir = NULL;
		wprintf(L"%s,CreateProcess fail.\n", Ttcommand);
		return -1;
	}
	delete[]pWCStrDir;
	pWCStrDir = NULL;
	ResumeThread(pi.hThread);

	char buffer[4096] = { 0 };
	DWORD nBytesToRead = 0;
	int doCnt = 3;
	std::string oneRe;
	while (true)
	{
		::memset(buffer, 0, sizeof(char) * 4096);
		//偷窥一下管道里是否有数据
		if (!PeekNamedPipe(hRead, buffer, 4095, &nBytesToRead, 0, 0))
		{
			break;
		}
		if (nBytesToRead <= 0)
		{
			doCnt--;
			if (doCnt <= 0)
			{
				break;
			}
			Sleep(800);
			continue;
		}
		//printf("bytes:%d\n", nBytesToRead);
		DWORD pDwRead = 0;
		::memset(buffer, 0, sizeof(char) * 4096);
		if (ReadFile(hRead, buffer, nBytesToRead, &pDwRead, NULL))
		{
			oneRe += buffer;
			if (std::string::npos != oneRe.find(matchOut))   //命中matchOut里的字符串
			{
				break;
			}
		}
	}//while
	if (debug)
	{
		printf("%s re:%s\n", sign.c_str(), oneRe.c_str());
	}
	CloseHandle(hWrite);
	CloseHandle(hRead);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}

int Ctl::AdbCmd(const std::string& cmd, std::string& pipe_data, int64_t timeout)
{
	char cCmd[1024] = { 0 };
	sprintf_s(cCmd, 1024, "cmd:%s\n", cmd.c_str());
	printf(cCmd);
	//开始时间
	auto start_time = std::chrono::steady_clock::now();

	single_page_buffer<char> pipe_buffer;

	HANDLE pipe_parent_read = INVALID_HANDLE_VALUE, pipe_child_write = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES sa_inherit{ .nLength = sizeof(SECURITY_ATTRIBUTES), .bInheritHandle = TRUE };
	if (!CreateOverlappablePipe(&pipe_parent_read, &pipe_child_write, nullptr, &sa_inherit,
		(DWORD)pipe_buffer.size(), true, false))
	{
		DWORD err = GetLastError();
		printf("CreateOverlappablePipe failed, %d\n", err);
		return -1;
	}

	STARTUPINFOW si{};
	si.cb = sizeof(STARTUPINFOW);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = pipe_child_write;
	si.hStdError = pipe_child_write;
	PROCESS_INFORMATION process_info = { nullptr }; // 进程信息结构体

	int cmdLen = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), (int)cmd.size(), nullptr, 0);
	std::filesystem::path::string_type cmdline_osstr(cmdLen, 0);
	MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), (int)cmd.size(), cmdline_osstr.data(), cmdLen);

	BOOL create_ret =
		CreateProcessW(nullptr, cmdline_osstr.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &process_info);
	if (!create_ret)
	{
		DWORD err = GetLastError();
		printf("Call %s create process failed, ret %d error code:%d\n", cmd.c_str(), create_ret, err);
		return -1;
	}

	CloseHandle(pipe_child_write);
	pipe_child_write = INVALID_HANDLE_VALUE;

	std::vector<HANDLE> wait_handles;
	wait_handles.reserve(2);
	bool process_running = true;
	bool pipe_eof = false;

	OVERLAPPED pipeov{ .hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr) };
	(void)ReadFile(pipe_parent_read, pipe_buffer.get(), (DWORD)pipe_buffer.size(), nullptr, &pipeov);

	while (1)
	{
		wait_handles.clear();
		if (process_running) wait_handles.push_back(process_info.hProcess);
		if (!pipe_eof) wait_handles.push_back(pipeov.hEvent);
		if (wait_handles.empty()) break;
		auto elapsed = std::chrono::steady_clock::now() - start_time;
		// TODO: 这里目前是隔 5000ms 判断一次，应该可以加一个 wait_handle 来判断外部中断 (need_exit)
		auto wait_time =(std::min)(timeout - duration_cast<std::chrono::milliseconds>(elapsed).count(), process_running ? 5LL * 1000 : 0LL);
		if (wait_time < 0) 
		{ 
			break; 
		}
		auto wait_result =WaitForMultipleObjectsEx((DWORD)wait_handles.size(), wait_handles.data(), FALSE, (DWORD)wait_time, TRUE);
		HANDLE signaled_object = INVALID_HANDLE_VALUE;
		if (wait_result >= WAIT_OBJECT_0 && wait_result < WAIT_OBJECT_0 + wait_handles.size())
		{
			signaled_object = wait_handles[(size_t)wait_result - WAIT_OBJECT_0];
		}
		else if (wait_result == WAIT_TIMEOUT)
		{
			if (wait_time == 0)
			{
				std::vector<std::string> handle_string{};
				for (auto handle : wait_handles)
				{
					if (handle == process_info.hProcess)
					{
						handle_string.emplace_back("process_info.hProcess");
					}
					else if (handle == pipeov.hEvent)
					{
						handle_string.emplace_back("pipeov.hEvent");
					}
					else
					{
						handle_string.emplace_back("UnknownHandle");
					}
				}
				printf("Wait handles:%s timeout.\n", handle_string.data()->c_str());
				if (process_running)
				{
					TerminateProcess(process_info.hProcess, 0);
				}
				break;
			}
			continue;
		}
		else
		{
			DWORD err = GetLastError();
			printf("A fatal error occurred\n");
			break;
		}

		if (signaled_object == process_info.hProcess)
		{
			process_running = false;
		}
		else if (signaled_object == pipeov.hEvent)
		{
			// pipe read
			DWORD len = 0;
			if (GetOverlappedResult(pipe_parent_read, &pipeov, &len, FALSE))
			{
				pipe_data.insert(pipe_data.end(), pipe_buffer.get(), pipe_buffer.get() + len);
				(void)ReadFile(pipe_parent_read, pipe_buffer.get(), (DWORD)pipe_buffer.size(), nullptr, &pipeov);
			}
			else
			{
				DWORD err = GetLastError();
				if (err == ERROR_HANDLE_EOF || err == ERROR_BROKEN_PIPE)
				{
					pipe_eof = true;
				}
			}
		}
	}

	auto end = std::chrono::steady_clock::now();
	std::chrono::duration<double> diff = end - start_time;
	std::cout << "Time:" << diff << "\n";

	DWORD exit_ret = 0;
	GetExitCodeProcess(process_info.hProcess, &exit_ret);
	CloseHandle(process_info.hProcess);
	CloseHandle(process_info.hThread);
	CloseHandle(pipe_parent_read);
	CloseHandle(pipeov.hEvent);
	return static_cast<int>(exit_ret);
}

bool Ctl::CreateOverlappablePipe(HANDLE* read, HANDLE* write, SECURITY_ATTRIBUTES* secattr_read, SECURITY_ATTRIBUTES* secattr_write, DWORD bufsize, bool overlapped_read, bool overlapped_write)
{
	static std::atomic<size_t> pipeid{};
	auto pipename = std::format(L"\\\\.\\pipe\\RabbitAdventure-pipe-{}-{}", GetCurrentProcessId(), pipeid++);
	DWORD read_flag = PIPE_ACCESS_INBOUND;
	if (overlapped_read) read_flag |= FILE_FLAG_OVERLAPPED;
	DWORD write_flag = GENERIC_WRITE;
	if (overlapped_write) write_flag |= FILE_FLAG_OVERLAPPED;
	auto pipe_read =
		CreateNamedPipeW(pipename.c_str(), read_flag, PIPE_TYPE_BYTE | PIPE_WAIT, 1, bufsize, bufsize, 0, secattr_read);
	if (pipe_read == INVALID_HANDLE_VALUE) return false;
	auto pipe_write =
		CreateFileW(pipename.c_str(), write_flag, 0, secattr_write, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (pipe_write == INVALID_HANDLE_VALUE)
	{
		CloseHandle(pipe_read);
		return false;
	}
	*read = pipe_read;
	*write = pipe_write;
	return true;
}

Ctl::~Ctl()
{

}

Dut::Dut(const std::string gUuid, bool gB_Shrink) :uuid(gUuid)
{
	bShrink = gB_Shrink;
}

Dut::~Dut()
{

}

int Dut::uuidConnect()
{
	if (std::string::npos != uuid.find("."))
	{
		std::string pipe_data;
		char buffer[1024] = { 0 };
		char funKey[MAX_PATH] = { 0 };
		sprintf_s(funKey, MAX_PATH, "adb.exe connect %s", uuid.c_str());
		int re = AdbCmd(funKey, pipe_data, 20000);
		printf("res:%s\n", pipe_data.c_str());
		if (false == (std::string::npos != pipe_data.find("connected to") || std::string::npos != pipe_data.find("already connected to")))
		{
			Sleep(2000);
			re = AdbCmd(funKey, pipe_data, 20000);
			printf("res:%s\n", pipe_data.c_str());
			if (false == (std::string::npos != pipe_data.find("connected to") || std::string::npos != pipe_data.find("already connected to")))
			{
				sprintf_s(buffer, 1024, "sleep 2s,adb connect %s again fail\n", uuid.c_str());
				printf(buffer);
				return -1;
			}
		}
	}//只对带有.号的adb devices name有效
	else
	{
		std::string pipe_data;
		char buffer[1024] = { 0 };
		char funKey[MAX_PATH] = { 0 };
		sprintf_s(funKey, MAX_PATH, "adb.exe devices");
		int re = AdbCmd(funKey, pipe_data, 20000);

		if (std::string::npos == pipe_data.find(uuid.c_str()))  //找不到uuid的值,说明设备没连接
		{
			sprintf_s(buffer, 1024, "%s found fail\n", uuid.c_str());
			printf(buffer);
			return -1;
		}
	}
	return 0;
}

Scrcpy::Scrcpy(const std::string gUuid,bool gB_Shrink) :Dut(gUuid,gB_Shrink)
{
	bStayAwak = false;
	bScreenOff = false;
	bFpsPrint = false;
	bTopAlways = false;
	bScreenOffIfExit = false;
	bBorderLess = false;
	bPositionX = false;
	bPositionY = false;
	bWidth = false;
	bHeight = false;
	positionX = 0;
	positionY = 0;
	scrcpyW = 0;
	scrcpyH = 0;

	bStartUp = false;
	handle = 0;
	hRead = 0;
	hWrite = 0;
	::memset(&si, 0, sizeof(si));
	pi = new PROCESS_INFORMATION();
}

Scrcpy::~Scrcpy()
{
	//被动释放资源
	disposing();
}

void Scrcpy::disposing()
{
	if (bStartUp)
	{
		CloseHandle(hWrite);
		CloseHandle(hRead);
		CloseHandle(pi->hThread);
		CloseHandle(pi->hProcess);
		bStartUp = false;
	}
	if (0 != handle)
	{
		CloseHandle(handle);
		handle = 0;
	}
	if (NULL != pi)
	{
		delete pi;
		pi = NULL;
	}
}

int Scrcpy::startUp()
{
	int re=uuidConnect();
	if (0 != re)
	{
		printf("uuidConnect fail\n");
		return -1;
	}
	
	std::string pipe_data;
	std::string cmd;
	if (bShrink) //是否收缩屏幕
	{
		cmd = "adb.exe -s " + uuid + " shell \"wm size 1080x1920 && echo $?\"";
	}
	else
	{
		cmd = "adb.exe -s " + uuid + " shell \"wm size reset && echo $?\"";
	}
	re = AdbCmd(cmd, pipe_data, 20000);
	printf("res:%s\n", pipe_data.c_str());
	if (std::string::npos!=pipe_data.find("error"))
	{
		re = uuidConnect();
		if (0 != re)
		{
			printf("uuidConnect again fail\n");
			return -1;
		}
	}

	handle = (HANDLE)_beginthreadex(//_beginthread 返回-1表示失败, 而_beginthreadex()返回0表示失败！
		NULL,                 // security
		0,                    // stack size
		&startUping,   //
		this,                 // arg list
		0,                    //立即运行 CREATE_SUSPENDED,// so we can later call ResumeThread()
		0);
	if (0 == handle)
	{
		printf("_beginthreadex fail\n");
		return -1;
	}
	//正常进while,等一下结果
	while (!bStartUp)
	{
		Sleep(800);
		printf("wait for bStartUp\n");
	}
	return 0;
}

int Scrcpy::stayAwakSet(bool enable)
{
	bStayAwak = enable;
	return 0;
}

int Scrcpy::screenOffSet(bool enable)
{
	bScreenOff = enable;
	return 0;
}

int Scrcpy::fpsPrintSet(bool enable)
{
	bFpsPrint = enable;
	return 0;
}

int Scrcpy::topAlwaysSet(bool enable)
{
	bTopAlways = enable;
	return 0;
}

int Scrcpy::screenOffIfExitSet(bool enable)
{
	bScreenOffIfExit = enable;
	return 0;
}

int Scrcpy::borderLessSet(bool enable)
{
	bBorderLess = enable;
	return 0;
}

int Scrcpy::positionX_Set(bool enable, int x)
{
	bPositionX = enable;
	positionX = x;
	return 0;
}

int Scrcpy::positionY_Set(bool enable, int y)
{
	bPositionY = enable;
	positionY = y;
	return 0;
}

int Scrcpy::widthSet(bool enable, int w)
{
	bWidth = enable;
	scrcpyW = w;
	return 0;
}

int Scrcpy::heightSet(bool enable, int h)
{
	bHeight = enable;
	scrcpyH = h;
	return 0;
}

int Dut::btnPress(int x, int y)
{
	char funKey[MAX_PATH] = { 0 };
	sprintf_s(funKey, MAX_PATH, "-s %s shell \"input tap %d %d && echo $?\"", uuid.c_str(), x, y);
	int re = AdbCmd(funKey, "0\n", __FUNCTION__);
	return re;
}

int Dut::btnPress(int x, int y, int duration_ms)
{
	//划动一个坐标来模拟按下事件,这样就可以观察到按钮被按下了
	//adb shell "input swipe 539/*x*/ 1298/*y*/ 540/*x+1*/ 1299/*y+1*/ 5000/*pressTime*/"
	char funKey[MAX_PATH] = { 0 };
	sprintf_s(funKey, MAX_PATH, "-s %s shell \" input swipe %d %d %d %d %d && echo $?\"", uuid.c_str(), x, y, x + 1, y + 1, duration_ms);
	int re = AdbCmd(funKey, "0\n", __FUNCTION__);
	return re;
}

int Dut::swipe(int sx, int sy, int ex, int ey, int duration_ms, bool waitOff)
{
	//划动一个坐标来模拟按下事件,这样就可以观察到按钮被按下了
	//adb shell "input swipe 539/*x*/ 1298/*y*/ 540/*x+1*/ 1299/*y+1*/ 5000/*pressTime*/"
	char funKey[MAX_PATH] = { 0 };
	sprintf_s(funKey, MAX_PATH, "-s %s shell \" input swipe %d %d %d %d %d && echo $?\"", uuid.c_str(), sx, sy, ex, ey, duration_ms);
	int re = AdbCmd(funKey, "0\n", __FUNCTION__);
	return re;
}

int Dut::motionMoveStart(int x1, int y1, int x2, int y2, int x3, int y3)
{
	//划动一个坐标来模拟按下事件,这样就可以观察到按钮被按下了
	//adb shell "input motionevent DOWN 135 135 && input motionevent MOVE 335 135 && input motionevent UP 135 200"
	char funKey[MAX_PATH] = { 0 };
	sprintf_s(funKey, MAX_PATH, "-s %s shell \"input motionevent DOWN %d %d && input motionevent MOVE %d %d && input motionevent MOVE %d %d && echo $?\"", uuid.c_str(), x1, y1, x2, y2, x3, y3);
	int re = AdbCmd(funKey, "0\n", __FUNCTION__);
	return re;
}

int Dut::motionMoveEnd(int x3, int y3)
{
	//划动一个坐标来模拟按下事件,这样就可以观察到按钮被按下了
	char funKey[MAX_PATH] = { 0 };
	sprintf_s(funKey, MAX_PATH, "-s %s shell \"input motionevent UP %d %d && echo $?\"", uuid.c_str(), x3, y3);
	int re = AdbCmd(funKey, "0\n", __FUNCTION__);
	return re;
}

Screenshot::Screenshot()
{

}

PcShot::PcShot()
{
	zoom = zoomGet();
	m_width = (int)(GetSystemMetrics(SM_CXSCREEN) * zoom);
	m_height = (int)(GetSystemMetrics(SM_CYSCREEN) * ((zoom * 1000 + 1) / 1000));
	m_screenshotData = new char[LONGLONG(m_width) * LONGLONG(m_height) * 4];      //不够大?
	memset(m_screenshotData, 0, m_width);

	// 获取屏幕 DC
	m_screenDC = GetDC(NULL);
	m_compatibleDC = CreateCompatibleDC(m_screenDC);

	// 创建位图
	m_hBitmap = CreateCompatibleBitmap(m_screenDC, m_width, m_height);
	SelectObject(m_compatibleDC, m_hBitmap);
}

PcShot::~PcShot()
{

}

cv::Mat PcShot::screenShotGet()
{
	// 得到位图的数据
	BitBlt(m_compatibleDC, 0, 0, m_width, m_height, m_screenDC, 0, 0, SRCCOPY);
	GetBitmapBits(m_hBitmap, m_width * m_height * 4, m_screenshotData);

	// 创建图像
	Mat screenshot(m_height, m_width, CV_8UC4, m_screenshotData);

	return screenshot;
}

cv::Mat PcShot::screenShotGet(int x, int y, int width, int height)
{
	cv::Mat screenshot = screenShotGet();
	return screenshot(Rect(x, y, width, height));
}

double PcShot::zoomGet()
{
	// 获取窗口当前显示的监视器
	HWND hWnd = GetDesktopWindow();
	HMONITOR hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);

	// 获取监视器逻辑宽度
	MONITORINFOEX monitorInfo;
	monitorInfo.cbSize = sizeof(monitorInfo);
	GetMonitorInfo(hMonitor, &monitorInfo);
	int cxLogical = (monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left);

	// 获取监视器物理宽度
	DEVMODE dm;
	dm.dmSize = sizeof(dm);
	dm.dmDriverExtra = 0;
	EnumDisplaySettings(monitorInfo.szDevice, ENUM_CURRENT_SETTINGS, &dm);
	int cxPhysical = dm.dmPelsWidth;

	return cxPhysical * 1.0 / cxLogical;
}

DutShot::DutShot(Dut* gDut)
{
	if (NULL == gDut)
	{
		printf("NULL==dut\n");
	}
	dut = gDut;
}

DutShot::~DutShot()
{

}

int DutShot::dutScreenShoetInPhone(bool debug)
{
	//adb.exe exec-out "screencap -p" > Pic/screen.png     //手机截屏到电脑,截不了,因为有个>
	//adb.exe exec-out "screencap -p|gzip" >a.png.gzip     //压缩手机截屏到电脑
	//adb.exe -s 32a5b74f shell \"LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/minicap -P 1080x2400@1080x2400/0 -s > /data/local/tmp/screen.png && echo $?\"
	std::string funKey = "-s " + dut->uuid + std::string(" exec-out \"screencap -p /data/local/tmp/screen.png && echo $?\" ");
	//std::string funKey = "-s " + dut->uuid + std::string(" shell \"LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/minicap -P 1080x2400@1080x2400/0 -s > /data/local/tmp/screen.png && echo $?\" ");
	int re = dut->AdbCmd(funKey, "0\n", __FUNCTION__, debug);
	return re;
}

int DutShot::dutScreenShoetPull(bool debug)
{
	char rmPath[MAX_PATH] = { 0 };
	sprintf_s(rmPath, "%s\\Pic\\screen.png", exePath.c_str());
	//删除screen
	if (0 == remove(rmPath))
	{
		//printf("rm screen.png success\n");
	}
	std::string funKey = "-s " + dut->uuid + std::string(" pull /data/local/tmp/screen.png Pic/screen.png");
	int re = dut->AdbCmd(funKey, "pulled.", __FUNCTION__, debug);
	return re;
}

cv::Mat DutShot::screenShotGet()
{
	LONGLONG t = cv::getTickCount();
	dutScreenShoetInPhone(true);
	dutScreenShoetPull(false);
	cv::Mat sc = cv::imread("Pic/screen.png", IMREAD_UNCHANGED);
	if (sc.empty())
	{
		printf("dut screen.png read fail\n");
		return cv::Mat();
	}
	//printf("time:%lf\n", (cv::getTickCount() - t) / cv::getTickFrequency());  //1秒多一张图,够不够用?先这样,后续再说
	/*cv::imshow("screen", sc);
	cv::waitKey(0);*/
	return sc;
}

DutFasterShot::DutFasterShot(Dut* gDut):DutShot(gDut)
{
	decode_raw_with_gzip = false;  //启不启用压缩,启用也挺慢的,而且,启用之后,只支持jpg格式,不支持png格式
}

DutFasterShot::~DutFasterShot()
{

}

cv::Mat DutFasterShot::screenShotGet()
{
	//minicap是jpg的,全部换成jpg再来一遍?
	//std::string cmd = "adb.exe -s 32a5b74f exec-out \"LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/minicap -P 1080x2400@1080x2400/0 -Q 100 -s 2>/dev/null\"";
	std::string cmd = "adb.exe -s " + dut->uuid + " exec-out \"screencap -p\"";
	if (decode_raw_with_gzip)
	{
		cmd = "adb.exe -s " + dut->uuid + " exec-out \"screencap | gzip -1\"";    //害惨我了,为什么这里不需要-p? 要p的你是不是不会阿?
	}
	std::string pipe_data;
	int exit_res = dut->AdbCmd(cmd, pipe_data, 20000);
	if (-1 == exit_res)
	{
		printf("call fail\n");
		//dut->AdbCmd("adb.exe kill-server", pipe_data, 15000);
		//容易掉adb,在这里起下scrcpy,adb
		Scrcpy* nDut = new Scrcpy((Scrcpy*)dut,dut->bShrink);
		dut->disposing();
		nDut->startUp();
		dut = nDut;      //偷梁换柱
		printf("wtf\n");
		return cv::Mat();
	}
	printf("pipeSize:%d\n", (int)pipe_data.size());

	//这里的进一步的解析
	if (decode_raw_with_gzip)
	{
		const std::string raw_data = decompress(pipe_data.data(), pipe_data.size());
		if (raw_data.size() < 8)
		{
			printf("raw_data.size<8\n");
			return cv::Mat();
		}
		// assuming little endian
		uint32_t w = static_cast<uint32_t>(static_cast<unsigned char>(raw_data[0])) << 0 |
			static_cast<uint32_t>(static_cast<unsigned char>(raw_data[1])) << 8 |
			static_cast<uint32_t>(static_cast<unsigned char>(raw_data[2])) << 16 |
			static_cast<uint32_t>(static_cast<unsigned char>(raw_data[3])) << 24;
		uint32_t h = static_cast<uint32_t>(static_cast<unsigned char>(raw_data[4])) << 0 |
			static_cast<uint32_t>(static_cast<unsigned char>(raw_data[5])) << 8 |
			static_cast<uint32_t>(static_cast<unsigned char>(raw_data[6])) << 16 |
			static_cast<uint32_t>(static_cast<unsigned char>(raw_data[7])) << 24;
		if (int(w) != m_width || int(h) != m_height)
		{
			printf("Size from image header %d %d does not match the size of screen %d %d\n", w, h, m_width, m_height);
			return cv::Mat();
		}
		size_t std_size = 4ULL * m_width * m_height;
		if (raw_data.size() < std_size)
		{
			printf("raw_data.size<std_size");
			return cv::Mat();
		}
		const size_t header_size = raw_data.size() - std_size; // 12 or 16. ref:
		auto img_data_beg = raw_data.cbegin() + header_size;
		cv::Mat image_payload(m_height, m_width, CV_8UC4, const_cast<char*>(&*img_data_beg));
		if (image_payload.empty())
		{
			printf("decode_raw_with_gzip if temp.empty()\n");
			return cv::Mat();
		}
		const auto& br = *(image_payload.end<cv::Vec4b>() - 1);
		if (br[3] != 255)    //黑屏的画面不要
		{   // only check alpha
			printf("br[3] != 255\n");
			return cv::Mat();
		}
		//要复制一下,不然就炸了
		cv::Mat dst(image_payload.size(), image_payload.type(), Scalar(0, 0, 0));
		//cv::cvtColor(image_payload, image_payload, cv::COLOR_RGBA2BGR);//丢掉透明度,那不就是jpg了?
		cv::cvtColor(image_payload, dst, cv::COLOR_RGBA2BGRA); //转成opencv认识的格式
		/*char pngPath[100] = { 0 };
		sprintf_s(pngPath, "Pic/0_src.png");
		cv::imwrite(pngPath, dst);*/
		return dst;
	}
	else
	{
		if (pipe_data.size() <= 0)
		{
			printf("decode_raw_with_gzip else pipe_data.size() <= 0\n");
			return cv::Mat();
		}
		cv::Mat image_payload = cv::imdecode({ pipe_data.data(), int(pipe_data.size()) }, cv::IMREAD_UNCHANGED);
		if (image_payload.empty())
		{
			printf("decode_raw_with_gzip else image_payload.empty()\n");
			return cv::Mat();
		}
		//char pngPath[100] = { 0 };
		//sprintf_s(pngPath, "Pic/%d_src.png", aIdx++);
		//cv::imwrite(pngPath, image_payload);
		return image_payload;
	}
}

DutMiniShot::DutMiniShot(Dut* gDut):DutShot(gDut)
{

}

DutMiniShot::~DutMiniShot()
{

}

cv::Mat DutMiniShot::screenShotGet()
{
	//minicap是jpg的,是不是这里指定一下长宽好一点
	std::string cmd = "adb.exe -s " + dut->uuid + " exec-out \"LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/minicap -P 1080x1920@1080x1920/0 -Q 100 -s 2>/dev/null\"";
	std::string pipe_data;
	int exit_res = dut->AdbCmd(cmd, pipe_data, 20000);
	if (-1 == exit_res)
	{
		printf("call fail\n");
		//dut->AdbCmd("adb.exe kill-server", pipe_data, 15000);
		//容易掉adb,在这里起下scrcpy,adb
		Scrcpy* nDut = new Scrcpy((Scrcpy*)dut,dut->bShrink);
		dut->disposing();
		nDut->startUp();
		dut = nDut;      //偷梁换柱
		printf("wtf\n");
		return cv::Mat();
	}
	printf("pipeSize:%d\n", (int)pipe_data.size());

	//这里的进一步的解析
	if (pipe_data.size() <= 0)
	{
		printf("pipe_data.size() <= 0\n");
		return cv::Mat();
	}
	cv::Mat image_payload = cv::imdecode({ pipe_data.data(), int(pipe_data.size()) }, cv::IMREAD_UNCHANGED);
	if (image_payload.empty())
	{
		printf("image_payload.empty()\n");
		return cv::Mat();
	}
	//char pngPath[100] = { 0 };
	//sprintf_s(pngPath, "Pic/%d_src.png", aIdx++);
	//cv::imwrite(pngPath, image_payload);
	return image_payload;
}

Motion::Motion(Dut* sc)
{
	dut = sc;
	Init();
	idleDisable = false;
}

Motion::~Motion()
{
	Close();  //要及时的释放
}

int Motion::PicDirectoryGen(const char* dirName)
{
	const char* execPath = exePath.c_str();
	//去掉运行程序名
	char noExePath[MAX_PATH] = { 0 };
	strcpy_s(noExePath, MAX_PATH, execPath);
#pragma warning(disable:4267)
	int len = strlen(noExePath);
#pragma warning(default:4267)
	//最后是.exe
	if (NULL != strstr(noExePath + (len - 4), ".exe"))
	{
		noExePath[strlen(noExePath) - 1] = '\0';
		char* tep = strrchr(noExePath, '\\');
		if (NULL != tep)
		{
			*tep = '\0';
		}
	}
	char picDirectory[MAX_PATH] = { 0 };
	sprintf_s(picDirectory, MAX_PATH, "%s\\%s", noExePath, dirName);

	int re = 0;
	//文件夹不存在则创建文件夹
	if (_access(picDirectory, 0) == -1)
	{
		//0==success,-1==fail
		re = _mkdir(picDirectory);
	}
	return re;
}

void Motion::detectHSColor(const Mat& image, double minHue, double maxHue, double minSat, double maxSat, Mat& mask)
{
	Mat hsv;
	Mat src;
	cv::cvtColor(image, hsv, CV_BGR2HSV);
	std::vector<Mat> channels;
	split(hsv, channels);
	Mat mask1, mask2, hueMask;
	cv::threshold(channels[0], mask1, maxHue, 255, THRESH_BINARY_INV);
	cv::threshold(channels[0], mask2, minHue, 255, THRESH_BINARY);
	if (minHue < maxHue)
	{
		hueMask = mask1 & mask2;
	}
	else
	{
		hueMask = mask1 | mask2;
	}
	Mat satMask;
	inRange(channels[1], minSat, maxSat, satMask);
	mask = hueMask & satMask;
}

int Motion::gameStartRun(const Mat& src, int sign, bool debug)
{
	//识别到开始游戏按钮后,返回中心坐标,按下按钮
	Mat btnMask;
	detectHSColor(src, 75, 83, 133, 169, btnMask);
	Mat maskSrc;
	src.copyTo(maskSrc, btnMask);
	/* cv::namedWindow("maskSrc", WINDOW_NORMAL);
	 cv::imshow("maskSrc", maskSrc);*/

	Mat graySrc;
	cv::cvtColor(maskSrc, graySrc, COLOR_BGR2GRAY);
	Mat binSrc;
	cv::threshold(graySrc, binSrc, 127, 255, THRESH_BINARY);

	std::vector<std::vector<Point>> contours;
	std::vector<Vec4i> hierarchy;
	cv::findContours(binSrc, contours, hierarchy, RETR_EXTERNAL, CHAIN_APPROX_SIMPLE);
	int lengthMaxIdx = -1;
	double lengthMax = 0;
	for (size_t aIdx = 0; aIdx < contours.size(); aIdx++)
	{
		double length = arcLength(contours[aIdx], 0);
		if (lengthMax < length)
		{
			lengthMax = length;
			lengthMaxIdx = (int)aIdx;
		}
	}
	RotatedRect btn;
	Mat drawSrc;
	src.copyTo(drawSrc);
	if (-1 != lengthMaxIdx)
	{
		Rect btn = boundingRect(contours[lengthMaxIdx]);
		rectangle(drawSrc, btn, Scalar(0, 0, 255), 3);
		printf("\t%d:btnRect,[%d,%d]==[%d X %d]\n", sign, btn.x, btn.y, btn.width, btn.height);
		std::string aChar = charRec(src(btn), sign);   //遇到不认为的会拋异常
		if (std::string::npos != aChar.find("开始游戏"))//找到 开始游戏 按钮了
		{
			printf("%d:gameStart btn matched\n", sign);

			//拿重心
			auto M = moments(contours[lengthMaxIdx]);
			int gameStartCx = int(M.m10 / M.m00);
			int gameStartCy = int(M.m01 / M.m00);
			if (!debug) //识别到绿色的开始游戏按钮了,不得按一下?
			{
				dut->btnPress(gameStartCx, gameStartCy);
			}
			return 0;
		}
	}//if (-1 != lengthMaxIdx)
	/*namedWindow("drawSrc", WINDOW_NORMAL);
	cv::imshow("drawSrc", drawSrc);
	cv::waitKey(0);*/
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/gameStart/%d_src_%d_%d.jpg", sign, static_cast<int>(btn.angle), static_cast<int>(btn.size.width));
	sprintf_s(namedrawsrc, 100, "Pic/gameStart/%d_drawsrc_%d_%d.jpg", sign, static_cast<int>(btn.angle), static_cast<int>(btn.size.width));
	cv::imwrite(namesrc, src);
	cv::imwrite(namedrawsrc, drawSrc);
	return -1;
}

int Motion::welcomeRun(const Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/welcome/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/welcome/%d_drawsrc.jpg", sign);

	//printf("type:%d\n", src.type());
	if (16 != src.type())
	{
		printf("16 != src.type()\n");
		return -1;
	}
	//图片是暗部与亮部组合而成的,让暗的更暗,以达到过滤小物体的作用
	Mat brightSrc = cv::Mat(src.size(), src.type());
	for (int aIdx = 0; aIdx < src.rows; aIdx++)
	{
		for (int bIdx = 0; bIdx < src.cols; bIdx++)
		{
			brightSrc.at<Vec3b>(aIdx, bIdx)[0] = saturate_cast<UINT8>(src.at<Vec3b>(aIdx, bIdx)[0] - 100);
			brightSrc.at<Vec3b>(aIdx, bIdx)[1] = saturate_cast<UINT8>(src.at<Vec3b>(aIdx, bIdx)[1] - 100);
			brightSrc.at<Vec3b>(aIdx, bIdx)[2] = saturate_cast<UINT8>(src.at<Vec3b>(aIdx, bIdx)[2] - 100);
		}
	}
	
	/*namedWindow("brightSrc", WINDOW_NORMAL);
	imshow("brightSrc", brightSrc);
	waitKey(0);*/
	//imwrite("Pic/brightSrc.png", brightSrc);

	cv::Mat brightGraySrc;
	cv::cvtColor(brightSrc, brightGraySrc, COLOR_BGR2GRAY);

	cv::Mat brightBinSrc;
	cv::threshold(brightGraySrc, brightBinSrc, 127, 255, THRESH_BINARY);

	cv::Mat brightDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(21, 21));
	Mat brightDilateSrc;
	cv::dilate(brightBinSrc, brightDilateSrc, brightDilateEle);
	/*cv::namedWindow("brightDilateSrc", WINDOW_NORMAL);
	cv::imshow("brightDilateSrc", brightDilateSrc);
	waitKey(0);*/

	std::vector<std::vector<Point>> brightContours;
	std::vector<Vec4i> brightHi;
	cv::findContours(brightDilateSrc, brightContours, brightHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	//因为背景变暗后,剩余的元素肯定少了,所以判断一下剩余元素,太多就不往下处理了
	int eleCnt = (int)brightContours.size();
	//printf("%d:has elems:%d\n", sign, eleCnt);
	if (eleCnt < 6 || eleCnt>14)  //6,11==>6,14
	{
		cv::imwrite(namesrc, src);
		return -1;
	}
	std::vector<int> x500MayIdx;
	for (int aIdx = 0; aIdx < brightContours.size(); aIdx++)
	{
		double length = arcLength(brightContours[aIdx], 0);
		//printf("i:%d,brightArch:%1f\n", aIdx, length); //打个锤子,打了有什么用吗?还不是识别不到
		if (length >= 100 && length < 550)    //剔掉一些离谱的值
		{
			x500MayIdx.push_back(aIdx);
		}
	}

	cv::Mat x500DrawSrc;
	src.copyTo(x500DrawSrc);

	//识别到x500的位置
	int x500Cx = -1;
	int x500Cy = -1;
	int gainCx = -1;
	int gainCy = -1;
	for (int aIdx = 0; aIdx < x500MayIdx.size(); aIdx++)
	{
		RotatedRect btn;
		Point2f vec[4];
		btn = minAreaRect(brightContours[x500MayIdx[aIdx]]);
		btn.points(vec);           //从左下角顺时针
		//printf("\tobtainRect,angle:%f,size:", btn.angle);
		//printf("[%d x %d]([%d,%d],[%d,%d],[%d,%d],[%d,%d])\n", (int)btn.size.width, (int)btn.size.height, (int)vec[0].x, (int)vec[0].y, (int)vec[1].x, (int)vec[1].y, (int)vec[2].x, (int)vec[2].y, (int)vec[3].x, (int)vec[3].y);
		RNG rng(cv::getTickCount());
		auto b = rng.uniform(0, 256);
		auto g = rng.uniform(0, 256);
		auto r = rng.uniform(0, 256);
		for (int j = 0; j < 4; j++)  //一条一条边绘制
		{
			cv::line(x500DrawSrc, vec[j], vec[(j + 1) % 4], Scalar(b, g, r), 3);
		}
		int x = (int)(vec[1].x - 10);
		int y = (int)(vec[1].y - 10);
		int w = (int)(vec[2].x - vec[1].x);
		int h = (int)(vec[3].y - vec[2].y);
		if (x <= 0 || y <= 0 || w > src.cols || h > src.rows || w <= 0 || h <= 0 || x + w > src.cols || y + h > src.rows)
		{
			//printf("x500,[x:%d,y:%d,w:%d,h:%d] err\n",x,y,w,h);
			continue;
		}
		std::string aChar = charRec(src(Rect(x, y, w, h)), sign);
		if (std::string::npos != aChar.find("普通领取"))//找到 普通领取 按钮了
		{
			//拿重心
			auto M = moments(brightContours[x500MayIdx[aIdx]]);
			gainCx = int(M.m10 / M.m00);
			gainCy = int(M.m01 / M.m00);
		}
		/*drawContours(x500DrawSrc, brightContours, x500MayIdx[aIdx], Scalar(0, 255, 0), 3);
		namedWindow("x500DrawSrc", WINDOW_NORMAL);
		imshow("x500DrawSrc", x500DrawSrc);
		waitKey(0);*/
	}
	//搞毛阿,如果找得到普通领取,那直接点击好了
	if (-1 != gainCx && -1 != gainCy)
	{
		if (!debug)
		{
			dut->btnPress(gainCx, gainCy);
		}
		else
		{
			printf("gain btn matched\n");
		}
		return 0;
	}
	else
	{
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, x500DrawSrc);
		return -1;
	}
}

int Motion::dailyLandingRun(const Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/dailyLanding/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/dailyLanding/%d_drawsrc.jpg", sign);

	/*namedWindow("src", WINDOW_NORMAL);
	imshow("src", src);*/

	int roiX = 860;
	int roiY = 300;
	int roiW = 140;
	int roiH = 140;
	if (1080 != src.cols && 1920 != src.rows)
	{
		printf("roi match fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}

	if (src.cols < roiX + roiW || src.rows < roiY + roiH)   //只对粉色按钮感兴趣
	{
		printf("roi fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	cv::Mat roi = src(cv::Rect(roiX, roiY, roiW, roiH));
	cv::Mat testRoi;
	src.copyTo(testRoi);
	cv::rectangle(testRoi, cv::Rect(860, 300, 140, 140), cv::Scalar(0, 0, 255), 5);
	cv::rectangle(roi, cv::Rect(1, 1, roiW-2, roiH-2), cv::Scalar(0, 255, 0), 1);
	/*namedWindow("testRoi", WINDOW_NORMAL);
	imshow("testRoi", testRoi);
	namedWindow("roi", WINDOW_NORMAL);
	imshow("roi", roi);
	waitKey(0);*/

	Mat btnMask;
	detectHSColor(roi, 163, 176, 53, 146, btnMask);
	Mat maskSrc;
	roi.copyTo(maskSrc, btnMask);
	/*namedWindow("maskSrc", WINDOW_NORMAL);
	imshow("maskSrc", maskSrc);*/

	Mat gaussSrc;
	//sigma = 0.3*((ksize-1)*0.5-1)+0.8
	cv::GaussianBlur(maskSrc, gaussSrc, Size(17, 17), 8.1);
	/*namedWindow("gaussSrc", WINDOW_NORMAL);
	imshow("gaussSrc", gaussSrc);*/

	cv::Mat graySrc;
	cv::cvtColor(gaussSrc, graySrc, COLOR_BGR2GRAY);
	/*namedWindow("graySrc", WINDOW_NORMAL);
	imshow("graySrc", graySrc);*/

	cv::Mat binSrc;
	cv::threshold(graySrc, binSrc, 127, 255, THRESH_BINARY);
	/*namedWindow("binSrc", WINDOW_NORMAL);
	imshow("binSrc", binSrc);
	waitKey(0);*/

	std::vector<std::vector<Point>> contours;
	std::vector<Vec4i> hierarchy;
	cv::findContours(binSrc, contours, hierarchy, RETR_LIST, CHAIN_APPROX_SIMPLE);   //识别轮廓还是用二值图好一点
	//查找最大周长
	int eleCnt = (int)contours.size();
	//printf("%d:has elems:%d\n", sign, eleCnt);
	if (2 != eleCnt)   //就一个按钮,轮廓识别只有两个东西,否则就有干扰
	{
		cv::imwrite(namesrc, src);
		return -1;
	}
	double maxArcLen = 0;
	int maxArcLenIdx = -1;
	for (size_t aIdx = 0; aIdx < contours.size(); aIdx++)
	{
		double length = arcLength(contours[aIdx], 0);
		//printf("\ti:%d,arcLength:%1f\n", (int)aIdx, length);
		if (length >= maxArcLen)  //这么大一块,他的大小应该不会随着屏幕大小而变化吧
		{
			maxArcLen = length;
			maxArcLenIdx = (int)aIdx;
		}
	}
	if (-1 == maxArcLenIdx)
	{
		printf("pink arch length err.\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	RotatedRect btn = minAreaRect(contours[maxArcLenIdx]);
	Point2f vertices[4];
	btn.points(vertices);           //从左下角顺时针
	for (int aIdx = 0; aIdx < 4; aIdx++)
	{
		vertices[aIdx].x = vertices[aIdx].x + roiX; //要加上roi的起始坐标
		vertices[aIdx].y = vertices[aIdx].y + roiY; //要加上roi的起始坐标
	}
	//printf("\tpinkCloseRect,angle:%f,size:", btn.angle);
	//printf("[%d x %d]([%d,%d],[%d,%d],[%d,%d],[%d,%d])\n", (int)btn.size.width, (int)btn.size.height, (int)vertices[0].x, (int)vertices[0].y, (int)vertices[1].x, (int)vertices[1].y, (int)vertices[2].x, (int)vertices[2].y, (int)vertices[3].x, (int)vertices[3].y);
	cv::Mat drawSrc;
	src.copyTo(drawSrc);
	for (int j = 0; j < 4; j++)  //一条一条边绘制
	{
		cv::line(drawSrc, vertices[j], vertices[(j + 1) % 4], Scalar(0, 0, 255), 3);
	}
	//namedWindow("drawSrc", WINDOW_NORMAL);
	////drawContours(drawSrc, contours, maxArcLenIdx, Scalar(0, 255, 0), 3);
	//imshow("drawSrc", drawSrc);
	//waitKey(0);
	auto M = moments(contours[maxArcLenIdx]);
	int btnCx = int(M.m10 / M.m00) + roiX;  //重心要加上roi的起始坐标
	int btnCy = int(M.m01 / M.m00) + roiY;
	//printf("\tbtnCxCy:[%d,%d]\n", btnCx, btnCy);//922,374 522,329/515,343
	if (btnCx > (917) && btnCx < (927) && btnCy >= (369) && btnCy <= (379))   //点落在某一范围内
	{
		if (!debug)
		{
			dut->btnPress(btnCx, btnCy);
		}
		else
		{
			printf("pink btn matched\n");
		}
		return 0;
	}
	cv::imwrite(namesrc, src);
	cv::imwrite(namedrawsrc, drawSrc);
	return -1;
}

static std::string base64Encode(const unsigned char* Data, int DataByte)
{
	//编码表
	const char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	//返回值
	std::string strEncode;
	unsigned char Tmp[4] = { 0 };
	int LineLength = 0;
	for (int i = 0; i < (int)(DataByte / 3); i++)
	{
		Tmp[1] = *Data++;
		Tmp[2] = *Data++;
		Tmp[3] = *Data++;
		strEncode += EncodeTable[Tmp[1] >> 2];
		strEncode += EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
		strEncode += EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
		strEncode += EncodeTable[Tmp[3] & 0x3F];
		if (LineLength += 4, LineLength == 76) { strEncode += "\n"; LineLength = 0; }
	}
	//对剩余数据进行编码
	int Mod = DataByte % 3;
	if (Mod == 1)
	{
		Tmp[1] = *Data++;
		strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
		strEncode += EncodeTable[((Tmp[1] & 0x03) << 4)];
		strEncode += "==";
	}
	else if (Mod == 2)
	{
		Tmp[1] = *Data++;
		Tmp[2] = *Data++;
		strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
		strEncode += EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
		strEncode += EncodeTable[((Tmp[2] & 0x0F) << 2)];
		strEncode += "=";
	}


	return strEncode;
}

static std::string Mat2Base64(const cv::Mat& img, std::string imgType)
{
	//Mat转base64
	std::string img_data;
	std::vector<uchar> vecImg;
	std::vector<int> vecCompression_params;
	vecCompression_params.push_back(CV_IMWRITE_JPEG_QUALITY);
	vecCompression_params.push_back(90);
	imgType = "." + imgType;
	cv::imencode(imgType, img, vecImg, vecCompression_params);
	img_data = base64Encode(vecImg.data(), (int)vecImg.size());
	return img_data;
}

static std::string base64Decode(const char* Data, int DataByte)
{
	//解码表
	const char DecodeTable[] =
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		62, // '+'
		0, 0, 0,
		63, // '/'
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
		0, 0, 0, 0, 0, 0, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
		0, 0, 0, 0, 0, 0,
		26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
	};
	//返回值
	std::string strDecode;
	int nValue;
	int i = 0;
	while (i < DataByte)
	{
		if (*Data != '\r' && *Data != '\n')
		{
			nValue = DecodeTable[*Data++] << 18;
			nValue += DecodeTable[*Data++] << 12;
			strDecode += (nValue & 0x00FF0000) >> 16;
			if (*Data != '=')
			{
				nValue += DecodeTable[*Data++] << 6;
				strDecode += (nValue & 0x0000FF00) >> 8;
				if (*Data != '=')
				{
					nValue += DecodeTable[*Data++];
					strDecode += nValue & 0x000000FF;
				}
			}
			i += 4;
		}
		else// 回车换行,跳过
		{
			Data++;
			i++;
		}
	}
	return strDecode;
}

static cv::Mat Base2Mat(std::string& base64_data)
{
	cv::Mat img;
	std::string s_mat;
	s_mat = base64Decode(base64_data.data(), (int)base64_data.size());
	std::vector<char> base64_img(s_mat.begin(), s_mat.end());
	img = cv::imdecode(base64_img, CV_LOAD_IMAGE_COLOR);
	return img;
}

int Motion::numRec(const Mat& src, int sign)
{
	try
	{
		int jpgNum = -1;
		LONGLONG t = cv::getTickCount();
		std::string imgbase64jpg = Mat2Base64(src, "jpg");
		//std::cout << imgbase64 << std::endl;
		/*cv::Mat outimg = Base2Mat(imgbase64);
		cv::imshow("test", outimg);
		cv::waitKey(0);*/
		char* resjpg = Classification(const_cast<char*>(imgbase64jpg.c_str()));
#pragma warning(disable:4267)
		int lenjpg = strlen(resjpg);
#pragma warning(default:4267)
		try
		{
			if (0 < lenjpg)
			{
				if (resjpg[0] >= '0' && resjpg[0] <= '9')
				{
					jpgNum = atoi(resjpg);
				}
				else if ('l' == resjpg[0]) //1识别成了l我日了
				{
					jpgNum = 1;
				}
				//printf("%d\n", num);
			}
			else
			{
				//printf("\t%d:jpg返回空字符串\n", sign);
			}
		}
		catch (const std::exception&)
		{
			printf("\t%d:jpg出错了,res==%s\n", sign, resjpg);
		}
		int pngNum = -1;
		if (0 >= jpgNum/*jpgNum有可能就是等于0*/)  //用jpg拿不到好值,换png试试
		{
			std::string imgbase64png = Mat2Base64(src, "png");
			char* respng = Classification(const_cast<char*>(imgbase64png.c_str()));
#pragma warning(disable:4267)
			int lenpng = strlen(respng);
#pragma warning(default:4267)
			try
			{
				if (0 < lenpng)
				{
					if (respng[0] >= '0' && respng[0] <= '9')
					{
						pngNum = atoi(respng);
					}
					else if ('l' == respng[0]) //1识别成了l我日了
					{
						pngNum = 1;
					}
					//printf("%d\n", num);
				}
				else
				{
					//printf("\t%d:png返回空字符串\n", sign);
				}
			}
			catch (const std::exception&)
			{
				printf("\t%d:png出错了,res==%s\n", sign, respng);
			}
		}
		//printf("time:%lf\n", (cv::getTickCount() - t) / cv::getTickFrequency());
		return jpgNum > pngNum ? jpgNum : pngNum;  //拿较大的回去
	}
	catch (const std::exception& e)
	{
		printf("%s\n", e.what());
		return -1;
	}
}

std::string Motion::charRec(const cv::Mat& src, int sign)
{
	try
	{
		std::string jpgChar = "";
		LONGLONG t = cv::getTickCount();
		std::string imgbase64jpg = Mat2Base64(src, "jpg");
		//std::cout << imgbase64 << std::endl;
		/*cv::Mat outimg = Base2Mat(imgbase64);
		cv::imshow("test", outimg);
		cv::waitKey(0);*/
		char* resjpg = Classification(const_cast<char*>(imgbase64jpg.c_str()));
#pragma warning(disable:4267)
		int lenjpg = strlen(resjpg);
#pragma warning(default:4267)
		try
		{
			if (0 < lenjpg)
			{
				jpgChar = resjpg;
				//printf("%d\n", num);
			}
			else
			{
				jpgChar = "";
				//printf("\t%d:jpg返回空字符串\n", sign);
			}
		}
		catch (const std::exception&)
		{
			printf("\t%d:jpg出错了,res==%s\n", sign, resjpg);
		}
		std::string pngChar = "";
		if (jpgChar.empty())  //用jpg拿不到好值,换png试试
		{
			std::string imgbase64png = Mat2Base64(src, "png");
			char* respng = Classification(const_cast<char*>(imgbase64png.c_str()));
#pragma warning(disable:4267)
			int lenpng = strlen(respng);
#pragma warning(default:4267)
			try
			{
				if (0 < lenpng)
				{
					pngChar = atoi(respng);
					//printf("%d\n", num);
				}
				else
				{
					pngChar = "";
					//printf("\t%d:png返回空字符串\n", sign);
				}
			}
			catch (const std::exception&)
			{
				printf("\t%d:png出错了,res==%s\n", sign, respng);
			}
		}
		//printf("time:%lf\n", (cv::getTickCount() - t) / cv::getTickFrequency());
		return jpgChar.empty() ? pngChar : jpgChar;  //拿较大的回去
	}
	catch (const std::exception& e)
	{
		printf("%s\n",e.what());
		return "";
	}
}

int Motion::checkPointsRun(const Mat& src, int sign, int checkNum, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/checkPoints/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/checkPoints/%d_drawsrc.jpg", sign);

	Mat numMask;
	detectHSColor(src, 3, 10, 15, 29, numMask);
	Mat numSrc;
	src.copyTo(numSrc, numMask);
	/*namedWindow("numSrc", WINDOW_NORMAL);
	imshow("numSrc", numSrc);*/

	cv::Mat numDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(33, 33));
	Mat numDilateSrc;
	cv::dilate(numSrc, numDilateSrc, numDilateEle);
	/*namedWindow("numDilateSrc", WINDOW_NORMAL);
	imshow("numDilateSrc", numDilateSrc);*/

	cv::Mat numGraySrc;
	cv::cvtColor(numDilateSrc, numGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("numGraySrc", WINDOW_NORMAL);
	imshow("numGraySrc", numGraySrc);*/

	Mat numBinSrc;
	cv::threshold(numGraySrc, numBinSrc, 127, 255, THRESH_BINARY);
	/*namedWindow("numBinSrc", WINDOW_NORMAL);
	imshow("numBinSrc", numBinSrc);*/

	Mat numDrawSrc;
	src.copyTo(numDrawSrc);
	std::vector<std::vector<Point>> numContours;
	std::vector<Vec4i> numHi;
	cv::findContours(numBinSrc, numContours, numHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	std::vector<std::vector<Point>>approx_contours(numContours.size());//存放逼近曲线的数组
	//drawContours(numDrawSrc, numContours, 1, Scalar(255, 0,0), 3);
	std::vector<int> mayNumVs; //可能是数字的索引
	for (int aIdx = 0; aIdx < numContours.size(); aIdx++)
	{
		approxPolyDP(numContours[aIdx], approx_contours[aIdx], 20, true);   //将点拟合,只留下四个端点的
		/*printf("%d:approx_contours:%d\n", aIdx, (int)approx_contours[aIdx].size());
		drawContours(numDrawSrc, approx_contours, aIdx, Scalar(0, 255, 0), 3);
		namedWindow("numDrawSrc", WINDOW_NORMAL);
		imshow("numDrawSrc", numDrawSrc);
		waitKey(0);*/
		if (4 == approx_contours[aIdx].size())
		{
			//drawContours(numDrawSrc, approx_contours, aIdx, Scalar(0, 255, 0), 3);
			mayNumVs.push_back(aIdx);
		}
	}

	typedef struct
	{
		int idx;
		int checkPoint;//第几关
		int cX;//中心坐标x
		int cY;//中心坐标y
	}check_s;

	std::vector<check_s> checkSet;  //每个矩形块保存的数据的集合
	for (int aIdx = 0; aIdx < mayNumVs.size(); aIdx++)
	{
		Rect numRect = boundingRect(approx_contours[mayNumVs[aIdx]]);
		rectangle(numDrawSrc, numRect, Scalar(255, 0, 0), 3);

		int nu = numRec(src(numRect), sign);
		if (0 < nu)//关卡数都是从1开始的,所以就算atoi识别到0回来也没事
		{
			auto M = moments(numContours[mayNumVs[aIdx]]);
			check_s cs;
			cs.checkPoint = nu;
			cs.cX = int(M.m10 / M.m00);
			cs.cY = int(M.m01 / M.m00);
			printf("firstMay:%d,[%d,%d]\n", nu, cs.cX, cs.cY);
			checkSet.push_back(cs);  //可能会识别错误的关卡数回来,需要根据y坐标来判断关卡数是否正常
		}

	}

	//条件判断阶段
	//只存识别了关卡数的坐标
	//再根据关卡的y坐标从小到大排列
	//中间的关卡要在中间,如果不在说明识别错了
	//最上面的关卡要比下面所有的关卡大
	//最下面的关卡要比下面所有的关卡小
	std::vector<check_s> check_ss_may;
	for (int aIdx = 0; aIdx < checkSet.size(); aIdx++)
	{
		if (-1 != checkSet[aIdx].checkPoint)
		{
			check_ss_may.push_back(checkSet[aIdx]);
		}
	}
	if (check_ss_may.size() > 0) //什么都没识别都就不用往下了
	{
		for (int aIdx = 0; aIdx < check_ss_may.size() - 1; aIdx++)
		{
			for (int bIdx = aIdx + 1; bIdx < check_ss_may.size(); bIdx++)
			{
				if (check_ss_may[aIdx].cY > check_ss_may[bIdx].cY)//按y的大小排序
				{
					auto t = check_ss_may[aIdx];
					check_ss_may[aIdx] = check_ss_may[bIdx];
					check_ss_may[bIdx] = t;
				}
			}
		}

		//识别到了,就说明关卡数成了
		for (int aIdx = 0; aIdx < check_ss_may.size(); aIdx++)
		{
			printf("pointMay:%d,[%d,%d]\n", check_ss_may[aIdx].checkPoint, check_ss_may[aIdx].cX, check_ss_may[aIdx].cY);
		}
		if (checkNum == check_ss_may[check_ss_may.size() - 1].checkPoint) //判断最后一个是不是1关卡,且相邻关卡相差不超过2
		{
			if (check_ss_may.size() >= 2)
			{
				if (check_ss_may[check_ss_may.size() - 1].checkPoint - check_ss_may[check_ss_may.size() - 2].checkPoint <= 2)
				{
					printf("checkPoint matched.\n");
					if (!debug)
					{
						dut->btnPress(check_ss_may[check_ss_may.size() - 1].cX, check_ss_may[check_ss_may.size() - 1].cY);
					}
					/*namedWindow("numDrawSrc", WINDOW_NORMAL);
					imshow("numDrawSrc", numDrawSrc);
					waitKey(0);*/
					return 0;
				}
			}
		}

		//没有识别到,往下划一下
		if (!debug)
		{
			int startX = src.cols / 2;
			int startY = src.rows / 2;
			if (startY < 320)
			{
				printf("swipe over y\n");
				cv::imwrite(namesrc, src);
				cv::imwrite(namedrawsrc, numDrawSrc);
				/*namedWindow("numDrawSrc", WINDOW_NORMAL);
				imshow("numDrawSrc", numDrawSrc);
				waitKey(0);*/
				return -1;
			}
			dut->swipe(startX, startY, startX, startY - 320);
			Sleep(1500);//屏幕还会划动一下的
		}
	}

	cv::imwrite(namesrc, src);
	cv::imwrite(namedrawsrc, numDrawSrc);
	/*namedWindow("numDrawSrc", WINDOW_NORMAL);
	imshow("numDrawSrc", numDrawSrc);
	waitKey(0);*/
	return -1;
}

int Motion::pointEnter(const cv::Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/pointEnter/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/pointEnter/%d_drawsrc.jpg", sign);

	//namedWindow("src", WINDOW_NORMAL);
	//imshow("src", src);

	//第一关的开始按钮
	cv::Mat btnMask;
	detectHSColor(src, 7, 13, 181, 246, btnMask);
	cv::Mat btnSrc;
	src.copyTo(btnSrc, btnMask);
	/*namedWindow("btnSrc", WINDOW_NORMAL);
	imshow("btnSrc", btnSrc);*/

	//获取结构
	cv::Mat erodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3));
	Mat erodeSrc;
	cv::erode(btnSrc, erodeSrc, erodeEle);
	/*namedWindow("erodeSrc", WINDOW_NORMAL);
	imshow("erodeSrc", erodeSrc);*/

	cv::Mat dilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3));
	Mat dilateSrc;
	cv::dilate(erodeSrc, dilateSrc, dilateEle);
	/*namedWindow("dilateSrc", WINDOW_NORMAL);
	imshow("dilateSrc", dilateSrc);*/

	cv::Mat btnGraySrc;
	cv::cvtColor(dilateSrc, btnGraySrc, COLOR_BGR2GRAY);

	Mat btnBinSrc;
	cv::threshold(btnGraySrc, btnBinSrc, 127, 255, THRESH_BINARY);
	/*namedWindow("btnBinSrc", WINDOW_NORMAL);
	imshow("btnBinSrc", btnBinSrc);*/

	std::vector<std::vector<Point>> contours;
	std::vector<Vec4i> hierarchy;
	cv::findContours(btnBinSrc, contours, hierarchy, RETR_LIST, CHAIN_APPROX_SIMPLE);
	std::vector<std::vector<Point>>approx_contours(contours.size());//存放逼近曲线的数组
	double maxArcLen = 0;
	int maxArcLenIdx = -1;
	Mat drawSrc;
	src.copyTo(drawSrc);
	for (int aIdx = 0; aIdx < contours.size(); aIdx++)
	{
		double length = arcLength(contours[aIdx], 0);
		approxPolyDP(contours[aIdx], approx_contours[aIdx], 65, true);   //将点拟合,只留下四个端点的
		//printf("\ti:%d,btnArcLength:%1f,apSize:%d\n", aIdx, length,(int)approx_contours[aIdx].size());
		if (length >= maxArcLen && 4 == approx_contours[aIdx].size())
		{
			maxArcLen = length;
			maxArcLenIdx = (int)aIdx;
		}
	}

	if (-1 == maxArcLenIdx)
	{
		printf("point arch -1\n");
		cv::imwrite(namesrc, src);
		return -1;
	}

	Rect btn = boundingRect(approx_contours[maxArcLenIdx]);
	rectangle(drawSrc, btn, Scalar(0, 255, 0), 3);
	/*namedWindow("drawSrc", WINDOW_NORMAL);
	imshow("drawSrc", drawSrc);
	waitKey(0);*/
	auto M = moments(approx_contours[maxArcLenIdx]);
	int cX = int(M.m10 / M.m00);
	int cY = int(M.m01 / M.m00);
	//printf("\tcenter:[%d,%d],size:[%d,%d]\n", cX, cY, btn.width, btn.height);
	//center:[533,1384],size:[270,127]
	if (cX >= (530) && cX <= (536) && cY >= (1381) && cY <= (1387) && btn.width >= 267 && btn.width <= 273 && btn.height >= 124 && btn.height <= 130)   //点落在某一范围内
	{
		printf("red btn matched\n");
		if (!debug)
		{
			dut->btnPress(cX, cY);
		}
		return 0;
	}
	cv::imwrite(namesrc, src);
	cv::imwrite(namedrawsrc, drawSrc);
	return -1;
}

int Motion::adventureEndStep(const cv::Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/endStep/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/endStep/%d_drawsrc.jpg", sign);

	//只关注roi里的时间,这要求长宽比保持不变
	int roiX = 950;
	int roiY = 372;
	int roiW = 100;
	int roiH = 70;
	if (1080 != src.cols || 1920 != src.rows)
	{
		printf("endStep roi match fail\n");
		cv::imwrite(namesrc, src);

		return -1;
	}

	if (src.cols < roiX + roiW || src.rows < roiY + roiH)   //只对特定区域感兴趣
	{
		printf("endStep roi fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	cv::Mat endStepRoi = src(cv::Rect(roiX, roiY, roiW, roiH));
	cv::Mat endStepDrawRoi = Mat(endStepRoi.size(), src.type());
	src(cv::Rect(roiX, roiY, roiW, roiH)).copyTo(endStepDrawRoi);
	cv::Mat test;
	src.copyTo(test);
	cv::rectangle(test, cv::Rect(950, 375, 100, 70), cv::Scalar(0, 0, 255), 5);
	cv::rectangle(endStepDrawRoi, cv::Rect(1, 1, roiW - 2, roiH - 2), cv::Scalar(0, 255, 0), 1);
	/*namedWindow("test", WINDOW_NORMAL);
	imshow("test", test);
	namedWindow("endStepRoi", WINDOW_NORMAL);
	imshow("endStepRoi", endStepRoi);
	waitKey(0);*/

	//判断一下是否有东西,再放过去,完全靠识别,他识别不了就乱给了.
	cv::Mat stepBkMask;
	detectHSColor(endStepRoi, 21, 29, 125, 210, stepBkMask);
	cv::Mat stepBkSrc;
	endStepRoi.copyTo(stepBkSrc, stepBkMask);
	/*namedWindow("stepBkSrc", WINDOW_NORMAL);
	imshow("stepBkSrc", stepBkSrc);*/

	cv::Mat stepBkGraySrc;
	cv::cvtColor(stepBkSrc, stepBkGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("stepBkGraySrc", WINDOW_NORMAL);
	imshow("stepBkGraySrc", stepBkGraySrc);*/

	Mat stepBkBinSrc;
	cv::threshold(stepBkGraySrc, stepBkBinSrc, 0, 255, THRESH_BINARY);

	cv::Mat stepBkDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3));
	Mat stepBkDilateSrc;
	cv::dilate(stepBkBinSrc, stepBkDilateSrc, stepBkDilateEle);
	/*namedWindow("stepBkDilateSrc", WINDOW_NORMAL);
	imshow("stepBkDilateSrc", stepBkDilateSrc);*/

	Mat gaussSrc;
	//sigma = 0.3*((ksize-1)*0.5-1)+0.8
	cv::GaussianBlur(stepBkDilateSrc, gaussSrc, Size(3, 3), 0.8);

	std::vector<std::vector<Point>> stepBkContours;
	std::vector<Vec4i> stepBkHi;
	cv::findContours(gaussSrc, stepBkContours, stepBkHi, RETR_EXTERNAL, CHAIN_APPROX_SIMPLE);  //垃圾,找东西都找不全
	double maxArcLen = 0;
	int maxArcLenIdx = -1;
	for (int aIdx = 0; aIdx < stepBkContours.size(); aIdx++)
	{
		double length = arcLength(stepBkContours[aIdx], 0);
		//printf("\t i:%d,endStepArch:%1f\n", aIdx, length);
		if (length >= maxArcLen)
		{
			maxArcLen = length;
			maxArcLenIdx = (int)aIdx;
		}
	}
	if (-1 == maxArcLenIdx)
	{
		printf("%d:step bk arch -1\n", sign);
		cv::imwrite(namesrc, src);
		return -1;
	}

	//不能用重心,比如7根本就不在中间,还是靠识别!!!
	//cv::Moments itemM = moments(stepBkContours[maxArcLenIdx],true);
	//int cX = int(itemM.m10 / itemM.m00);
	//int cY = int(itemM.m01 / itemM.m00);
	//printf("%d:bigOneCxCy:[%d,%d]\n",sign,cX,cY);//bigOneCxCy:[46,34]
	Rect bigOne = boundingRect(stepBkContours[maxArcLenIdx]);
	drawContours(endStepDrawRoi, stepBkContours, -1, cv::Scalar(255, 0, 0), 1);
	rectangle(endStepDrawRoi, bigOne, cv::Scalar(0, 255, 0), 1);

	/*namedWindow("endStepRoi", WINDOW_NORMAL);
	imshow("endStepRoi", endStepRoi);
	namedWindow("endStepDrawRoi", WINDOW_NORMAL);
	imshow("endStepDrawRoi", endStepDrawRoi);
	namedWindow("finally", WINDOW_NORMAL);
	imshow("finally", src(Rect(roiX + bigOne.x, roiY + bigOne.y, bigOne.width, bigOne.height)));*/

	//waitKey(0);
	int endStep = -1;
	int nu = numRec(src(Rect(roiX + bigOne.x, roiY + bigOne.y, bigOne.width, bigOne.height)), sign);
	if (-1 != nu)
	{
		endStep = nu;
		printf("%d:endStep:%d\n", sign, nu);
	}

	if (-1 == endStep)
	{
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, endStepDrawRoi);
	}
	return endStep;
}

int Motion::adventureEndCnt(const cv::Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/endCnt/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/endCnt/%d_drawsrc.jpg", sign);

	//只关注roi里的时间,这要求长宽比保持不变
	int roiX = 560;
	int roiY = 355;
	int roiW = 65;
	int roiH = 65;
	if (1080 != src.cols || 1920 != src.rows)
	{
		printf("endCnt roi match fail\n");
		cv::imwrite(namesrc, src);

		return -1;
	}

	if (src.cols < roiX + roiW || src.rows < roiY + roiH)   //只对特定区域感兴趣
	{
		printf("endCnt roi fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	cv::Mat endCntRoi = src(cv::Rect(roiX, roiY, roiW, roiH));
	cv::Mat endCntDrawRoi = Mat(endCntRoi.size(), src.type());    //画图操作全在这上面
	src(cv::Rect(roiX, roiY, roiW, roiH)).copyTo(endCntDrawRoi);  //画图操作全在这上面
	/*cv::Mat test;
	src.copyTo(test);
	cv::rectangle(test, cv::Rect(560, 355, 65, 65), cv::Scalar(0, 0, 255), 5);
	cv::rectangle(endCntRoi, cv::Rect(1, 1, roiW - 2, roiH - 2), cv::Scalar(0, 255, 0), 1);
	namedWindow("test", WINDOW_NORMAL);
	imshow("test", test);
	namedWindow("endCntRoi", WINDOW_NORMAL);
	imshow("endCntRoi", endCntRoi);
	waitKey(0);*/

	//剩余目标个数
	cv::Mat endCntMask;
	detectHSColor(endCntRoi, 173, 176, 74, 175, endCntMask);
	cv::Mat endCntSrc;
	endCntRoi.copyTo(endCntSrc, endCntMask);
	/*namedWindow("endCntSrc", WINDOW_NORMAL);
	imshow("endCntSrc", endCntSrc);*/

	cv::Mat endCntEilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(11, 11));
	Mat endCntDilateSrc;
	cv::dilate(endCntSrc, endCntDilateSrc, endCntEilateEle);
	/*namedWindow("endCntDilateSrc", WINDOW_NORMAL);
	imshow("endCntDilateSrc", endCntDilateSrc);*/

	/*cv::Mat endCntErodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(3, 3));
	Mat endCntErodeSrc;
	cv::erode(endCntSrc, endCntErodeSrc, endCntErodeEle);
	namedWindow("endCntErodeSrc", WINDOW_NORMAL);
	imshow("endCntErodeSrc", endCntErodeSrc);*/


	cv::Mat endCntGraySrc;
	cv::cvtColor(endCntDilateSrc, endCntGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("endCntGraySrc", WINDOW_NORMAL);
	imshow("endCntGraySrc", endCntGraySrc);*/

	Mat endCntBinSrc;
	cv::threshold(endCntGraySrc, endCntBinSrc, 0, 127, THRESH_BINARY);
	/*namedWindow("endCntBinSrc", WINDOW_NORMAL);
	imshow("endCntBinSrc", endCntBinSrc);
	waitKey(0);*/

	std::vector<std::vector<Point>> endCntContours;
	std::vector<Vec4i> endCmtHi;
	cv::findContours(endCntBinSrc, endCntContours, endCmtHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	std::vector<std::vector<Point>>approx_contours(endCntContours.size());     //存放逼近曲线的数组
	std::vector<int> mayEndCntIdxs;
	
	for (int aIdx = 0; aIdx < endCntContours.size(); aIdx++)
	{
		double length = arcLength(endCntContours[aIdx], 0);
		approxPolyDP(endCntContours[aIdx], approx_contours[aIdx], 15, true);   //将点拟合,只留下四个端点的
		/*printf("\ti:%d,endCntArcLength:%lf,apSize:%d\n", aIdx, length,(int)approx_contours[aIdx].size());
		namedWindow("endCntDrawRoi", WINDOW_NORMAL);
		drawContours(endCntDrawRoi, approx_contours, aIdx, Scalar(255, 0, 0), 3);
		imshow("endCntDrawRoi", endCntDrawRoi);
		waitKey(0);*/
		if (length >= 100 && length <= 170 && 4 == approx_contours[aIdx].size())
		{
			mayEndCntIdxs.push_back(aIdx);
		}
	}

	int endCnt = -1;
	for (int aIdx = 0; aIdx < mayEndCntIdxs.size(); aIdx++)
	{
		Rect endCntAround = boundingRect(endCntContours[mayEndCntIdxs[aIdx]]);
		auto endCntM = moments(endCntContours[mayEndCntIdxs[aIdx]]);
		int cx = int(endCntM.m10 / endCntM.m00);
		int cy = int(endCntM.m01 / endCntM.m00);
		printf("\t%d:cx,cy:[%d,%d],sizes:[%d,%d]\n", sign, cx, cy, endCntAround.width, endCntAround.height);
		rectangle(endCntDrawRoi, endCntAround, Scalar(0, 255, 0), 1);
		//cx,cy:[33,34],sizes:[30,43]/cx,cy:[32,35],sizes:[32,44]
		if (cx >= 31 && cx <= 35 && cy >= 32 && cy <= 36 && endCntAround.width >= 28 && endCntAround.width <= 32 && endCntAround.height >= 41 && endCntAround.height <= 45)
		{
			//记得转换坐标
			int nu = numRec(src(Rect(roiX+endCntAround.x,roiY+ endCntAround.y,endCntAround.width,endCntAround.height)), sign);
			/*namedWindow("numRec", WINDOW_NORMAL);
			imshow("numRec", src(Rect(roiX + endCntAround.x, roiY + endCntAround.y, endCntAround.width, endCntAround.height)));
			waitKey(0);*/
			if (-1!=nu)
			{
				printf("%d:endCnt:%d\n", sign, nu);
				endCnt = nu;
				break;
			}
		}
	}
	//namedWindow("endCntDrawSrc", WINDOW_NORMAL);
	////drawContours(endCntDrawSrc, endCntContours, 2, Scalar(255, 0, 0), 3);
	//imshow("endCntDrawSrc", endCntDrawSrc);
	//waitKey(0);
	if (-1 == endCnt)
	{
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, endCntDrawRoi);
	}
	return endCnt;
}

int Motion::adventureEndTime(const cv::Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/endTime/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/endTime/%d_drawsrc.jpg", sign);

	//只关注roi里的时间,这要求长宽比保持不变
	int roiX = 147;
	int roiY = 330;
	int roiW = 90;
	int roiH = 70;
	if (1080 != src.cols || 1920 != src.rows)
	{
		printf("endTime roi match fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}

	if (src.cols < roiX + roiW || src.rows < roiY + roiH)   //只对特定区域感兴趣
	{
		printf("endTime roi fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	cv::Mat endTimeRoi = src(cv::Rect(roiX, roiY, roiW, roiH));
	cv::Mat endTimeDrawRoi = Mat(endTimeRoi.size(), src.type());
	src(cv::Rect(roiX, roiY, roiW, roiH)).copyTo(endTimeDrawRoi);

	cv::Mat test;
	src.copyTo(test);
	cv::rectangle(test, cv::Rect(147, 330, 90, 70), cv::Scalar(0, 0, 255), 5);
	cv::rectangle(endTimeDrawRoi, cv::Rect(1, 1, roiW - 2, roiH - 2), cv::Scalar(0, 255, 0), 1);
	//namedWindow("test", WINDOW_NORMAL);
	//imshow("test", test);
	//namedWindow("endTimeRoi", WINDOW_NORMAL);
	//imshow("endTimeRoi", endTimeRoi);
	//waitKey(0);

	int endTime = -1;
	int nu = numRec(endTimeRoi, sign);
	if (-1 != nu)
	{
		endTime = nu;
		printf("%d:endTime:%d\n", sign, nu);
	}
	if (-1 == endTime)
	{
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, endTimeRoi);
	}
	return endTime;
}

int Motion::adventureSudo(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& sudoWidth, int& sudoHeight, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/adventure/%d_sudoSrc.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/adventure/%d_sudoDrawSrc.jpg", sign);

	//只关注roi里的时间,这要求长宽比保持不变
	int roiX = 0;
	int roiY = 501;
	int roiW = 1080;
	int roiH = 1080;
	if (1080 != src.cols || 1920 != src.rows)
	{
		printf("sudo roi match fail\n");
		cv::imwrite(namesrc, src);

		return -1;
	}

	if (src.cols < roiX + roiW || src.rows < roiY + roiH)   //只对特定区域感兴趣
	{
		printf("sudo roi fail\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	cv::Mat sudoRoi = src(cv::Rect(roiX, roiY, roiW, roiH));
	cv::Mat sudoDrawRoi = Mat(sudoRoi.size(), src.type());
	src(cv::Rect(roiX, roiY, roiW, roiH)).copyTo(sudoDrawRoi);

	/*cv::Mat test;
	src.copyTo(test);
	cv::rectangle(test, cv::Rect(0, 501, 1080, 1080), cv::Scalar(0, 0, 255), 5);*/
	cv::rectangle(sudoDrawRoi, cv::Rect(1, 1, roiW - 2, roiH - 2), cv::Scalar(0, 255, 0), 1);
	/*namedWindow("sudoDrawRoi", WINDOW_NORMAL);
	imshow("sudoDrawRoi", sudoDrawRoi);*/

	//需要判断一下到底是不是roi页面?
	//判断一下是否有东西,再放过去,完全靠识别,他识别不了就乱给了.
	cv::Mat sudoBkMask;
	detectHSColor(sudoRoi, 105, 108, 156, 195, sudoBkMask);
	cv::Mat sudoBkSrc;
	sudoRoi.copyTo(sudoBkSrc, sudoBkMask);
	/*namedWindow("sudoBkSrc", WINDOW_NORMAL);
	imshow("sudoBkSrc", sudoBkSrc);*/

	//printf("type:%d\n", src.type());
	if (16 != src.type())
	{
		printf("16 != src.type()\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	//图片是暗部与亮部组合而成的,让暗的更暗,以达到过滤暗面的作用
	Mat brightSrc = cv::Mat(sudoBkSrc.size(), sudoBkSrc.type());
	for (int aIdx = 0; aIdx < sudoBkSrc.rows; aIdx++)
	{
		for (int bIdx = 0; bIdx < sudoBkSrc.cols; bIdx++)
		{
			brightSrc.at<Vec3b>(aIdx, bIdx)[0] = saturate_cast<UINT8>(sudoBkSrc.at<Vec3b>(aIdx, bIdx)[0] - 100);
			brightSrc.at<Vec3b>(aIdx, bIdx)[1] = saturate_cast<UINT8>(sudoBkSrc.at<Vec3b>(aIdx, bIdx)[1] - 100);
			brightSrc.at<Vec3b>(aIdx, bIdx)[2] = saturate_cast<UINT8>(sudoBkSrc.at<Vec3b>(aIdx, bIdx)[2] - 100);
		}
	}
	/*namedWindow("brightSrc", WINDOW_NORMAL);
	imshow("brightSrc", brightSrc);*/

	cv::Mat sudoBkGraySrc;
	cv::cvtColor(brightSrc, sudoBkGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("sudoBkGraySrc", WINDOW_NORMAL);
	imshow("sudoBkGraySrc", sudoBkGraySrc);*/

	Mat sudoBkBinSrc;
	cv::threshold(sudoBkGraySrc, sudoBkBinSrc, 0, 255, THRESH_BINARY);
	/*namedWindow("sudoBkBinSrc", WINDOW_NORMAL);
	imshow("sudoBkBinSrc", sudoBkBinSrc);*/

	cv::Mat sudoBkDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(23, 23));
	Mat sudoBkDilateSrc;
	cv::dilate(sudoBkBinSrc, sudoBkDilateSrc, sudoBkDilateEle);
	/*namedWindow("sudoBkDilateSrc", WINDOW_NORMAL);
	imshow("sudoBkDilateSrc", sudoBkDilateSrc);*/
	//waitKey(0);

	std::vector<std::vector<Point>> sudoBkContours;
	std::vector<Vec4i> sudoBkHi;
	cv::findContours(sudoBkDilateSrc, sudoBkContours, sudoBkHi, RETR_EXTERNAL, CHAIN_APPROX_SIMPLE);  //垃圾,找东西都找不全
	double maxArea = 0;
	int maxAreaIdx = -1;
	for (int aIdx = 0; aIdx < sudoBkContours.size(); aIdx++)
	{
		double area = contourArea(sudoBkContours[aIdx], 0);
		//printf("\t %d:sudoArea:%1f\n", aIdx, area);
		if (area >= maxArea)
		{
			maxArea = area;
			maxAreaIdx = aIdx;
		}
	}
	if (-1 == maxAreaIdx)
	{
		printf("%d:sudo bk area -1\n", sign);
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, sudoBkBinSrc);
		return -1;
	}
	else if (maxArea < 1100000)   //这个数字是抓了几次图作为的分界线,后续应该不用改了吧
	{
		printf("%d:sudo bk area:[%lf] fail\n", sign, maxArea);
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, sudoBkBinSrc);
		return -1;
	}

	/*Rect bigOne = boundingRect(sudoBkContours[maxAreaIdx]);
	drawContours(sudoDrawRoi, sudoBkContours, -1, cv::Scalar(255, 0, 0), 1);
	rectangle(sudoDrawRoi, bigOne, cv::Scalar(0, 0, 255), 3);
	namedWindow("sudoDrawRoi", WINDOW_NORMAL);
	imshow("sudoDrawRoi", sudoDrawRoi);*/
	//waitKey(0);

	sudoLeftTopX = roiX;
	sudoLeftTopY = roiY;
	sudoWidth = roiW;
	sudoHeight = roiH;

	//只在原图上保存sudo的区域
	sudoSrc = cv::Mat(src.size(), src.type(), Scalar(0, 0, 0));
	for (int aIdx = sudoLeftTopY; aIdx < roiY + roiH; aIdx++)
	{
		for (int bIdx = sudoLeftTopX; bIdx < roiX + roiW; bIdx++)
		{
			sudoSrc.at<Vec3b>(aIdx, bIdx) = src.at<Vec3b>(aIdx, bIdx);
		}
	}
	/*namedWindow("sudoSrc", WINDOW_NORMAL);
	imshow("sudoSrc", sudoSrc);
	waitKey(0);*/

	return 0;
}

int Motion::adventureItemsByMoli(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& sudoWidth, int& sudoHeight, int& blockWidth, int& blockHeight, cv::Mat& calDrawSrc, blockItem_s* itemByMolis, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char nametxtdrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/adventure/%d_moliSrc.jpg", sign);
	sprintf_s(nametxtdrawsrc, 100, "Pic/adventure/%d_moliDrawSrc.jpg", sign);

	const int itR = 8;
	const int itCol = 8;
	cv::Mat moliMask;
	detectHSColor(src, 34, 105, 2, 111, moliMask);
	cv::Mat moliTextureSrc;  //带有纹理的白萝卜矩阵
	src.copyTo(moliTextureSrc, moliMask);
	/*namedWindow("moliTextureSrc", WINDOW_NORMAL);
	imshow("moliTextureSrc", moliTextureSrc);*/

	cv::Mat moliTextureErodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(5, 5));
	Mat moliTextureErodeSrc;
	cv::erode(moliTextureSrc, moliTextureErodeSrc, moliTextureErodeEle);
	/*namedWindow("moliTextureErodeSrc", WINDOW_NORMAL);
	imshow("moliTextureErodeSrc", moliTextureErodeSrc);*/

	cv::Mat moliTextureDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(5, 5));
	Mat moliTextureDilateSrc;
	cv::dilate(moliTextureErodeSrc, moliTextureDilateSrc, moliTextureDilateEle);
	/*namedWindow("moliTextureDilateSrc", WINDOW_NORMAL);
	imshow("moliTextureDilateSrc", moliTextureDilateSrc);*/

	cv::Mat moliSrc;
	//用sudo的背景还有白萝卜纹理做位与勾出白萝卜
	cv::bitwise_and(moliTextureDilateSrc, sudoSrc, moliSrc);
	/*namedWindow("moliSrc", WINDOW_NORMAL);
	imshow("moliSrc", moliSrc);*/

	cv::Mat moliErodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(11, 11));
	Mat moliErodeSrc;
	cv::erode(moliSrc, moliErodeSrc, moliErodeEle);
	/*namedWindow("moliErodeSrc", WINDOW_NORMAL);
	imshow("moliErodeSrc", moliErodeSrc);*/

	cv::Mat moliDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(11, 11));
	Mat moliDilateSrc;
	cv::dilate(moliSrc, moliDilateSrc, moliDilateEle);
	/*namedWindow("moliDilateSrc", WINDOW_NORMAL);
	imshow("moliDilateSrc", moliDilateSrc);*/

	cv::Mat moliGraySrc;
	cv::cvtColor(moliDilateSrc, moliGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("moliGraySrc", WINDOW_NORMAL);
	imshow("moliGraySrc", moliGraySrc);*/

	Mat moliBinSrc;
	cv::threshold(moliGraySrc, moliBinSrc, 0, 127, THRESH_BINARY);
	/*namedWindow("moliBinSrc", WINDOW_NORMAL);
	imshow("moliBinSrc", moliBinSrc);*/

	std::vector<std::vector<Point>> moliContours;
	std::vector<Vec4i> moliHi;
	cv::findContours(moliBinSrc, moliContours, moliHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	std::vector<int> mayMoliIdxs;
	//得到白萝卜的外接矩形,坐标,继而推算出整个数独的布局
	//获得白萝卜最小外接矩形
	for (int aIdx = 0; aIdx < moliContours.size(); aIdx++)
	{
		double length = arcLength(moliContours[aIdx], 0);
		//printf("\t i:%d,moliArcLength:%1f\n", aIdx, length);
		if (length >= 100)
		{
			mayMoliIdxs.push_back(aIdx);
		}
	}
	Mat moliDrawSrc;
	src.copyTo(moliDrawSrc);
	std::vector<point_s> moliVs;
	std::vector<int> moliWidthSet;   //白萝卜的宽集合
	std::vector<int> moliHeightSet;  //白萝卜的高集合
	for (int aIdx = 0; aIdx < mayMoliIdxs.size(); aIdx++)
	{
		Rect itemRec = boundingRect(moliContours[mayMoliIdxs[aIdx]]);
		point_s tmpItem;
		tmpItem.ltx = itemRec.x;
		tmpItem.lty = itemRec.y;
		tmpItem.rbx = itemRec.x + itemRec.width;
		tmpItem.rby = itemRec.y + itemRec.height;
		auto M = moments(moliContours[mayMoliIdxs[aIdx]]);
		tmpItem.cx = int(M.m10 / M.m00);
		tmpItem.cy = int(M.m01 / M.m00);
		moliVs.push_back(tmpItem);
		moliWidthSet.push_back(itemRec.width);
		moliHeightSet.push_back(itemRec.height);
		//printf("width:%d,height:%d\n", rightBottomX - leftTopX, rightBottomY - leftTopY);
	}//for
	//cv::namedWindow("moliDrawSrc", WINDOW_NORMAL);
	//cv::imshow("moliDrawSrc", moliDrawSrc);
	//获得白萝卜众数大小,这样就可以推断出整个sudo的布局,等于用cabbages来做验证
	int modeWidth = -1; //众数宽度
	int modeHight = -1; //众数高度
	int moliWidthModeCnt = 1;  //白萝卜宽度的最大众数个数
	int modeWidthIdx = -1;     //白萝卜宽度的最大众数所在索引
	sort(moliWidthSet.begin(), moliWidthSet.end());//排序,现在相同的都聚在一起了
	for (int aIdx = 0; aIdx < moliWidthSet.size() - 1; aIdx++)
	{
		int cnt = 1;
		for (int bIdx = aIdx + 1; bIdx < moliWidthSet.size(); bIdx++)
		{
			if (moliWidthSet[aIdx] == moliWidthSet[bIdx])//存在连续两个数相等，则众数+1
			{
				cnt++;
			}
			else
			{
				break;
			}
		}
		if (moliWidthModeCnt < cnt)
		{
			moliWidthModeCnt = cnt;   //当前最大众数个数
			modeWidthIdx = aIdx;      //当前众数标记位置
		}
	}
	if (-1 == modeWidthIdx)
	{
		printf("-1==modeWidthIdx\n");
		return -1;
	}

	int moliHeightModeCnt = 1;  //最大众数个数
	int modeHeightIdx = -1;
	sort(moliHeightSet.begin(), moliHeightSet.end());//排序,现在相同的都聚在一起了
	for (int aIdx = 0; aIdx < moliHeightSet.size() - 1; aIdx++)
	{
		int cnt = 1;
		for (int bIdx = aIdx + 1; bIdx < moliHeightSet.size(); bIdx++)
		{
			if (moliHeightSet[aIdx] == moliHeightSet[bIdx])//存在连续两个数相等，则众数+1
			{
				cnt++;
			}
			else
			{
				break;
			}
		}
		if (moliHeightModeCnt < cnt)
		{
			moliHeightModeCnt = cnt;   //当前最大众数个数
			modeHeightIdx = aIdx;      //当前众数标记位置
		}
	}
	if (-1 == modeHeightIdx)
	{
		printf("-1==modeHeightIdx\n");
		return -1;
	}
	//计算出sudo小格子的理论长宽与坐标
	blockWidth = (int)(sudoWidth / 8.0); //(int)round(sudoWidth / 8.0);
	blockHeight = (int)(sudoHeight / 8.0); //(int)round(sudoHeight / 8.0);
	printf("moliModeWH[%d,%d],calWH[%d,%d],sudoWH[%d,%d],sudoBlockWH[%d,%d]\n", moliWidthSet[modeWidthIdx], moliHeightSet[modeHeightIdx], 8 * moliWidthSet[modeWidthIdx], 8 * moliHeightSet[modeHeightIdx], sudoWidth, sudoHeight, blockWidth, blockHeight);

	if (sudoWidth < 8 * moliWidthSet[modeWidthIdx] || sudoHeight < 8 * moliHeightSet[modeHeightIdx])
	{
		printf("sudoWidth:%d < 8 * %d || sudoHeight:%d < 8 * %d\n", sudoWidth, moliWidthSet[modeWidthIdx], sudoHeight, moliHeightSet[modeHeightIdx]);
		cv::imwrite(namesrc, src);
		cv::imwrite(nametxtdrawsrc, moliDrawSrc);
		return -1;
	}

	for (int aIdx = 0; aIdx < 8; aIdx++)
	{
		for (int bIdx = 0; bIdx < 8; bIdx++)
		{
			RNG rng(cv::getTickCount());
			auto b = rng.uniform(0, 256);
			auto g = rng.uniform(0, 256);
			auto r = rng.uniform(0, 256);
			int ltx = sudoLeftTopX + bIdx * blockWidth;
			int lty = sudoLeftTopY + aIdx * blockHeight;
			rectangle(calDrawSrc, Rect(ltx, lty, blockWidth, blockHeight), Scalar(b, g, r), 2);
			itemByMolis[aIdx * itCol + bIdx].pt.ltx = ltx;
			itemByMolis[aIdx * itCol + bIdx].pt.lty = lty;
			itemByMolis[aIdx * itCol + bIdx].pt.rbx = ltx + blockWidth;
			itemByMolis[aIdx * itCol + bIdx].pt.rby = lty + blockHeight;
			itemByMolis[aIdx * itCol + bIdx].pt.cx = -1;
			itemByMolis[aIdx * itCol + bIdx].pt.cy = -1;
			itemByMolis[aIdx * itCol + bIdx].bMatched = false;
			itemByMolis[aIdx * itCol + bIdx].type = item_null;
		}
	}
	//用白萝卜的重心判断白萝卜有没有在理论方块内,有说明白萝卜在这里
	for (int cIdx = 0; cIdx < moliVs.size(); cIdx++)
	{
		for (int aIdx = 0; aIdx < 8; aIdx++)
		{
			for (int bIdx = 0; bIdx < 8; bIdx++)
			{
				int cx = moliVs[cIdx].cx;
				int cy = moliVs[cIdx].cy;
				if (cx > itemByMolis[aIdx * itCol + bIdx].pt.ltx && cx< itemByMolis[aIdx * itCol + bIdx].pt.rbx && cy> itemByMolis[aIdx * itCol + bIdx].pt.lty && cy < itemByMolis[aIdx * itCol + bIdx].pt.rby)
				{
					itemByMolis[aIdx * itCol + bIdx].pt.cx = cx;
					itemByMolis[aIdx * itCol + bIdx].pt.cy = cy;
					itemByMolis[aIdx * itCol + bIdx].bMatched = true;
					itemByMolis[aIdx * itCol + bIdx].type = moli_e;
				}
			}
		}
		cv::circle(calDrawSrc, cv::Point(moliVs[cIdx].cx, moliVs[cIdx].cy), 2, Scalar(0, 0, 255), 2);
	}
	/*cv::namedWindow("calDrawSrc", WINDOW_NORMAL);
	cv::imshow("calDrawSrc", calDrawSrc);
	waitKey(0);*/
	return 0;
}

int Motion::adventureItemsByCabbage(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& blockWidth, int& blockHeight, cv::Mat& calDrawSrc, blockItem_s* itemByCabbages, int sign, bool debug)
{
	const int itR = 8;
	const int itCol = 8;
	cv::Mat cabbageMask;
	detectHSColor(src, 38, 47, 175, 255, cabbageMask);
	cv::Mat cabbageTextureSrc;
	src.copyTo(cabbageTextureSrc, cabbageMask);
	/*namedWindow("cabbageTextureSrc", WINDOW_NORMAL);
	imshow("cabbageTextureSrc", cabbageTextureSrc);*/

	cv::Mat cabbageErodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(7, 7));
	Mat cabbageTextureErodeSrc;
	cv::erode(cabbageTextureSrc, cabbageTextureErodeSrc, cabbageErodeEle);
	/*namedWindow("cabbageTextureErodeSrc", WINDOW_NORMAL);
	imshow("cabbageTextureErodeSrc", cabbageTextureErodeSrc);*/

	cv::Mat cabbageDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(9, 9));
	Mat cabbageTextureDilateSrc;
	cv::dilate(cabbageTextureErodeSrc, cabbageTextureDilateSrc, cabbageDilateEle);
	/*namedWindow("cabbageTextureDilateSrc", WINDOW_NORMAL);
	imshow("cabbageTextureDilateSrc", cabbageTextureDilateSrc);*/

	cv::Mat cabbageSrc;
	cv::bitwise_and(cabbageTextureDilateSrc, sudoSrc, cabbageSrc);
	/*namedWindow("cabbageSrc", WINDOW_NORMAL);
	imshow("cabbageSrc", cabbageSrc);*/

	//用卷心菜的外接矩形,坐标,反向验证数独的布局
	cv::Mat cabbageGraySrc;
	cv::cvtColor(cabbageSrc, cabbageGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("cabbageGraySrc", WINDOW_NORMAL);
	imshow("cabbageGraySrc", cabbageGraySrc);*/

	Mat cabbageBinSrc;
	cv::threshold(cabbageGraySrc, cabbageBinSrc, 0, 127, THRESH_BINARY);
	/*namedWindow("cabbageBinSrc", WINDOW_NORMAL);
	imshow("cabbageBinSrc", cabbageBinSrc);*/

	std::vector<std::vector<Point>> cabbageContours;
	std::vector<Vec4i> cabbageHi;
	cv::findContours(cabbageBinSrc, cabbageContours, cabbageHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	Mat cabbageDrawSrc;
	src.copyTo(cabbageDrawSrc);
	//cv::namedWindow("cabbageDrawSrc", WINDOW_NORMAL);
	std::vector<int> mayCabbagesIdxs;
	for (int aIdx = 0; aIdx < cabbageContours.size(); aIdx++)
	{
		double length = arcLength(cabbageContours[aIdx], 0);
		//printf("\t i:%d,cabbageArcLength:%1f\n", aIdx, length);
		if (length >= 50)
		{
			mayCabbagesIdxs.push_back(aIdx);
		}
	}
	std::vector<point_s> cabbageVs;
	for (int aIdx = 0; aIdx < mayCabbagesIdxs.size(); aIdx++)
	{
		//cv::drawContours(cabbageDrawSrc, cabbageContours, mayCabbagesIdxs[aIdx], Scalar(0, 0, 255), 3);
		RotatedRect itemRec = minAreaRect(cabbageContours[mayCabbagesIdxs[aIdx]]);
		Point2f itemVec[4];
		itemRec.points(itemVec);           //从左下角顺时针
		//printf("\tcabbageRec,angle:%f,size:", itemRec.angle);
		//printf("[%d x %d]([%d,%d],[%d,%d],[%d,%d],[%d,%d])\n", (int)itemRec.size.width, (int)itemRec.size.height, (int)itemVec[0].x, (int)itemVec[0].y, (int)itemVec[1].x, (int)itemVec[1].y, (int)itemVec[2].x, (int)itemVec[2].y, (int)itemVec[3].x, (int)itemVec[3].y);
		int leftTopX = 9999;
		int leftTopY = 9999;
		int rightBottomX = -1;
		int rightBottomY = -1;
		for (int bIdx = 0; bIdx < 4; bIdx++)
		{
			//cv::line(cabbageDrawSrc, itemVec[bIdx], itemVec[(bIdx + 1) % 4], Scalar(0, 0, 255), 1);
			if (itemVec[bIdx].x < leftTopX)
			{
				leftTopX = (int)floor(itemVec[bIdx].x);
			}
			if (itemVec[bIdx].y < leftTopY)
			{
				leftTopY = (int)floor(itemVec[bIdx].y);
			}
			if (itemVec[bIdx].x > rightBottomX)
			{
				rightBottomX = (int)ceil(itemVec[bIdx].x);
			}
			if (itemVec[bIdx].y > rightBottomY)
			{
				rightBottomY = (int)ceil(itemVec[bIdx].y);
			}
		}//for
		point_s tmpItem;
		tmpItem.ltx = leftTopX;
		tmpItem.lty = leftTopY;
		tmpItem.rbx = rightBottomX;
		tmpItem.rby = rightBottomY;
		auto M = moments(cabbageContours[mayCabbagesIdxs[aIdx]]);
		tmpItem.cx = int(M.m10 / M.m00);
		tmpItem.cy = int(M.m01 / M.m00);
		cabbageVs.push_back(tmpItem);
		//printf("width:%d,height:%d\n", rightBottomX - leftTopX, rightBottomY - leftTopY);
	}

	for (int aIdx = 0; aIdx < 8; aIdx++)
	{
		for (int bIdx = 0; bIdx < 8; bIdx++)
		{
			RNG rng(cv::getTickCount());
			auto b = rng.uniform(0, 256);
			auto g = rng.uniform(0, 256);
			auto r = rng.uniform(0, 256);
			int ltx = sudoLeftTopX + bIdx * blockWidth;
			int lty = sudoLeftTopY + aIdx * blockHeight;
			rectangle(calDrawSrc, Rect(ltx, lty, blockWidth, blockHeight), Scalar(b, g, r), 2);
			itemByCabbages[aIdx * itCol + bIdx].pt.ltx = ltx;
			itemByCabbages[aIdx * itCol + bIdx].pt.lty = lty;
			itemByCabbages[aIdx * itCol + bIdx].pt.rbx = ltx + blockWidth;
			itemByCabbages[aIdx * itCol + bIdx].pt.rby = lty + blockHeight;
			itemByCabbages[aIdx * itCol + bIdx].pt.cx = -1;
			itemByCabbages[aIdx * itCol + bIdx].pt.cy = -1;
			itemByCabbages[aIdx * itCol + bIdx].bMatched = false;
			itemByCabbages[aIdx * itCol + bIdx].type = item_null;
		}
	}

	for (int cIdx = 0; cIdx < cabbageVs.size(); cIdx++)
	{
		for (int aIdx = 0; aIdx < 8; aIdx++)
		{
			for (int bIdx = 0; bIdx < 8; bIdx++)
			{
				int cx = cabbageVs[cIdx].cx;
				int cy = cabbageVs[cIdx].cy;
				if (cx > itemByCabbages[aIdx * itCol + bIdx].pt.ltx && cx< itemByCabbages[aIdx * itCol + bIdx].pt.rbx && cy> itemByCabbages[aIdx * itCol + bIdx].pt.lty && cy < itemByCabbages[aIdx * itCol + bIdx].pt.rby)
				{
					itemByCabbages[aIdx * itCol + bIdx].pt.cx = cx;
					itemByCabbages[aIdx * itCol + bIdx].pt.cy = cy;
					itemByCabbages[aIdx * itCol + bIdx].bMatched = true;
					itemByCabbages[aIdx * itCol + bIdx].type = cabbage_e;
				}
			}
		}
		cv::circle(calDrawSrc, cv::Point(cabbageVs[cIdx].cx, cabbageVs[cIdx].cy), 2, Scalar(255, 0, 0), 2);
	}
	/*cv::namedWindow("calDrawSrc", WINDOW_NORMAL);
	cv::imshow("calDrawSrc", calDrawSrc);
	waitKey(0);*/
	return 0;
}

int Motion::LinkPathGen(blockItem_s* blockItems, itemType_e type, bool bMostlySearch, std::deque<DATA_S>& linkPath, int sign, bool debug)
{
	const int itCol = 8;
	typedef struct _NODE_S
	{
		int startX;
		int startY;
		int endX;
		int endY;
	}NODE_S;

	std::vector<NODE_S> v2;
	//根据数组坐标,九宫格规则,类型,生成两点间有向边的信息
	for (int row = 0; row < 8; row++)
	{
		for (int col = 0; col < 8; col++)
		{
			if (type == blockItems[row * itCol + col].type)
			{
				NODE_S node;
				//左上
				if (row - 1 >= 0 && col - 1 >= 0)
				{
					auto cmp = blockItems[(row - 1) * itCol + (col - 1)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row - 1;
						node.endY = col - 1;
						v2.push_back(node);
					}
				}
				//上
				if (row - 1 >= 0)
				{
					auto cmp = blockItems[(row - 1) * itCol + (col)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row - 1;
						node.endY = col;
						v2.push_back(node);
					}
				}
				//右上
				if (row - 1 >= 0 && col + 1 <= 8 - 1)
				{
					auto cmp = blockItems[(row - 1) * itCol + (col + 1)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row - 1;
						node.endY = col + 1;
						v2.push_back(node);
					}
				}
				//左
				if (col - 1 >= 0)
				{
					auto cmp = blockItems[(row)*itCol + (col - 1)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row;
						node.endY = col - 1;
						v2.push_back(node);
					}
				}
				//右
				if (col + 1 <= 8 - 1)
				{
					auto cmp = blockItems[(row)*itCol + (col + 1)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row;
						node.endY = col + 1;
						v2.push_back(node);
					}
				}
				//左下
				if (row + 1 <= 8 - 1 && col - 1 >= 0)
				{
					auto cmp = blockItems[(row + 1) * itCol + (col - 1)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row + 1;
						node.endY = col - 1;
						v2.push_back(node);
					}
				}
				//下
				if (row + 1 <= 8 - 1)
				{
					auto cmp = blockItems[(row + 1) * itCol + (col)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row + 1;
						node.endY = col;
						v2.push_back(node);
					}
				}
				//右下
				if (row + 1 <= 8 - 1 && col + 1 <= 8 - 1)
				{
					auto cmp = blockItems[(row + 1) * itCol + (col + 1)].type;
					if (blockItems[row * itCol + col].type == cmp)
					{
						node.startX = row;
						node.startY = col;
						node.endX = row + 1;
						node.endY = col + 1;
						v2.push_back(node);
					}
				}
			}//if type判断
		}//for
	}//for
	std::vector<std::deque<DATA_S>> v3;
	LONGLONG t = cv::getTickCount();
	//根据v2生成v3,即3点间有效的有向边的信息
	for (int aIdx = 0; aIdx < v2.size(); aIdx++)
	{
		//拿到开始A与结尾B,用结尾B去v2里面去找开始C与结尾D
		//B与C相同,即为找到了,找到后跟D与A比较,不同就串上去
		auto enterX = v2[aIdx].startX;
		auto enterY = v2[aIdx].startY;
		//将信息推到堆栈里去,后面比较要用

		auto LeaveX = v2[aIdx].endX;
		auto LeaveY = v2[aIdx].endY;
		bool bFound = false;
		for (int bIdx = 0; bIdx < v2.size(); bIdx++)
		{
			if (!bFound)
			{
				//首次找到结尾
				if (LeaveX == v2[bIdx].startX && LeaveY == v2[bIdx].startY)
				{
					//在v2搜索到的结尾不能又连回enter了
					if (false == (enterX == v2[bIdx].endX && enterY == v2[bIdx].endY))
					{
						bFound = true;
						//[enterX,enterY]->[LeaveX,LeaveY]->(v2[bIdx].endX,v2[bIdx].endY)
						std::deque<DATA_S> dq;
						DATA_S d1;
						d1.x = enterX;
						d1.y = enterY;
						dq.push_back(d1);
						d1.x = LeaveX;
						d1.y = LeaveY;
						dq.push_back(d1);
						d1.x = v2[bIdx].endX;
						d1.y = v2[bIdx].endY;
						dq.push_back(d1);
						v3.push_back(dq);
					}
				}
			}
			else
			{
				if (LeaveX != v2[bIdx].startX || LeaveY != v2[bIdx].startY) //前面同一点已经处理完了
				{
					break;
				}
				//在v2搜索到的结尾不能又连回enter了
				if (false == (enterX == v2[bIdx].endX && enterY == v2[bIdx].endY))
				{
					//[enterX,enterY]->[LeaveX,LeaveY]->(v2[bIdx].endX,v2[bIdx].endY)
					std::deque<DATA_S> dq;
					DATA_S d1;
					d1.x = enterX;
					d1.y = enterY;
					dq.push_back(d1);
					d1.x = LeaveX;
					d1.y = LeaveY;
					dq.push_back(d1);
					d1.x = v2[bIdx].endX;
					d1.y = v2[bIdx].endY;
					dq.push_back(d1);
					v3.push_back(dq);
				}
			}
		}
	}
	printf("v3time:%lf\n", (cv::getTickCount() - t) / cv::getTickFrequency());
	linkPath = v3[0];
	if (bMostlySearch)
	{
		//根据v3生成vn,想办法探到最深,只保留最深那一层的
		//算法不完善,没办法全部探完,也就探个90%吧
		std::vector<std::deque<DATA_S>> vTest = v3;
		std::deque<DATA_S> vMostDepth;
		std::vector<std::deque<DATA_S>> vMostDepths;
		t = cv::getTickCount();
		for (long aIdx = 0; aIdx < vTest.size(); aIdx++)
		{
			std::deque<DATA_S> maxPoints;
			std::vector<DATA_S> cmpPoints;
			int eIdx = 3;     //从第3个起点开始,可以有分叉
			std::deque<DATA_S> opV = vTest[aIdx];
			int doCnt = 0;
			int dqSize = 0;
			do
			{
				doCnt = 0;
				dqSize = 0;
				do
				{
					doCnt++;
					int searchX = opV[opV.size() - 1].x;
					int searchY = opV[opV.size() - 1].y;
					dqSize = (int)opV.size();
					for (int bIdx = 0; bIdx < v2.size(); bIdx++)
					{
						//命中了搜索坐标且在队列中没出现过的坐标
						if (searchX == v2[bIdx].startX && searchY == v2[bIdx].startY)
						{
							bool bSame = false;
							for (int cIdx = 0; cIdx < opV.size(); cIdx++)
							{
								if (opV[cIdx].x == v2[bIdx].endX && opV[cIdx].y == v2[bIdx].endY)
								{
									bSame = true;
									break;
								}
								for (int dIdx = 0; dIdx < cmpPoints.size(); dIdx++)
								{
									if (v2[bIdx].endX == cmpPoints[dIdx].x && v2[bIdx].endY == cmpPoints[dIdx].y)
									{
										bSame = true;
										break;
									}
								}
								if (bSame)
								{
									break;
								}
							}
							if (bSame)
							{
								continue;
							}
							//没有在队列中命中,即这是个全新的顶点
							std::deque<DATA_S> dq = opV;
							DATA_S d1;
							d1.x = v2[bIdx].endX;;
							d1.y = v2[bIdx].endY;;
							dq.push_back(d1);
							opV = dq;
							break;
						}
					}//二点区间for搜索
					if (opV.size() == dqSize)
					{
						//运行了一遍添加的操作,但是并没有添加,说明已经探到最深了
						break;
					}
				} while (doCnt <= 30);
				//printf("maxPoints:%d,opV:%d\n", maxPoints.size(),opV.size());
				//探到一条7的,怎么换下一条探?
				if (opV.size() > maxPoints.size())
				{
					maxPoints = opV;
				}
				if (eIdx >= maxPoints.size())
				{
					if (vMostDepth.size() > 0)
					{
						if (maxPoints.size() > vMostDepth.size())
						{
							vMostDepth = maxPoints;
						}
					}
					else
					{
						vMostDepth = maxPoints;
					}
					vMostDepths.push_back(maxPoints);
					break;
				}
				cmpPoints.push_back(maxPoints[eIdx]);
				opV.clear();
				for (int bIdx = 0; bIdx < eIdx; bIdx++)
				{
					opV.push_back(maxPoints[bIdx]);
				}
				eIdx++;
			} while (true);
		}
		printf("vMostDepthTime:%lf\n", (cv::getTickCount() - t) / cv::getTickFrequency());
		linkPath = vMostDepth;
	}
	return 0;
}

void Motion::idleOp(int sign, bool bFaster, bool debug)
{
	char key = 0;
	if (!debug)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
		}
		if ('q' == key)
		{
			idleDisable = true;
		}
		else if ('s' == key)
		{
			idleDisable = false;
		}
		if (idleDisable)
		{
			return;
		}
		//int startX = src.cols / 2;
		//int startY = src.rows / 2;
		int startX = 1080 / 2;    //先固定吧
		int startY = 2400 / 2;    //先固定吧,反正手机是不变的
		int step = 55;
		while (_kbhit())
		{
			key = _getch();
			printf("key1==%c\n", key);
		}
		if ('q' == key)
		{
			idleDisable = true;
		}
		else if ('s' == key)
		{
			idleDisable = false;
		}
		dut->swipe(startX, startY, startX + step, startY, 1000, bFaster);
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
		}
		if ('q' == key)
		{
			idleDisable = true;
		}
		else if ('s' == key)
		{
			idleDisable = false;
		}
		//dut->swipe(startX + step, startY, startX, startY, 1000, bFaster);  //只划一个区域
	}
}

int Motion::adventureRun(const cv::Mat& src, itemType_e targetType, bool bIncomeMax/*是否收益最大化*/, bool bMostlySearch, int& targetMatchCnt/*实际连起来的数量*/, int sign, bool debug)
{
	//printf("targetType:%d\n", targetType);
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/adventure/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/adventure/%d_drawsrc.jpg", sign);

	/*namedWindow("src", WINDOW_NORMAL);
	imshow("src", src);*/

	cv::Mat sudoSrc;
	int sudoLeftTopX = 9999;
	int sudoLeftTopY = 9999;
	int sudoWidth = -1;
	int sudoHeight = -1;
	int re = adventureSudo(src, sudoSrc, sudoLeftTopX, sudoLeftTopY, sudoWidth, sudoHeight, sign, debug);
	if (-1 == re)
	{
		printf("sudo detech fail.\n");
		cv::imwrite(namesrc, src);
		return -1;
	}

	int blockWidth = -1;
	int blockHeight = -1;
	Mat calDrawSrc;
	src.copyTo(calDrawSrc);
	blockItem_s itemByMolis[8][8];
	re = adventureItemsByMoli(src, sudoSrc, sudoLeftTopX, sudoLeftTopY, sudoWidth, sudoHeight, blockWidth, blockHeight, calDrawSrc, itemByMolis[0], sign, debug);
	if (-1 == re)
	{
		printf("moli detech fail.\n");
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, calDrawSrc);
		return -1;
	}
	/*printf("moli:\n");
	for (int aIdx = 0; aIdx < 8; aIdx++)
	{
		for (int bIdx = 0; bIdx < 8; bIdx++)
		{
			printf("%d ", itemByMolis[aIdx][bIdx].type);
		}
		printf("\n");
	}*/

	blockItem_s itemByCabbages[8][8];
	re = adventureItemsByCabbage(src, sudoSrc, sudoLeftTopX, sudoLeftTopY, blockWidth, blockHeight, calDrawSrc, itemByCabbages[0], sign, debug);
	if (-1 == re)
	{
		printf("cabbage detech fail.\n");
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, calDrawSrc);
		return -1;
	}
	/*printf("cabbage:\n");
	for (int aIdx = 0; aIdx < 8; aIdx++)
	{
		for (int bIdx = 0; bIdx < 8; bIdx++)
		{
			printf("%d ", itemByCabbages[aIdx][bIdx].type);
		}
		printf("\n");
	}*/

	//没验证上的话,就让鼠标在屏幕中间左右划动下,防止出奇怪的东西
	for (int aIdx = 0; aIdx < 8; aIdx++)
	{
		for (int bIdx = 0; bIdx < 8; bIdx++)
		{
			if (item_null == itemByMolis[aIdx][bIdx].type && item_null == itemByCabbages[aIdx][bIdx].type || itemByMolis[aIdx][bIdx].bMatched && itemByCabbages[aIdx][bIdx].bMatched)
			{
				printf("moli match cabbage arr fail.\n");
				idleOp(sign, debug);
				cv::imwrite(namesrc, src);
				cv::imwrite(namedrawsrc, calDrawSrc);
				return -1;
			}
		}
	}
	blockItem_s blockItems[8][8] = { 0 };
	printf("mix:\n");
	for (int aIdx = 0; aIdx < 8; aIdx++)
	{
		for (int bIdx = 0; bIdx < 8; bIdx++)
		{
			if (itemByMolis[aIdx][bIdx].bMatched)
			{
				blockItems[aIdx][bIdx] = itemByMolis[aIdx][bIdx];
			}
			if (itemByCabbages[aIdx][bIdx].bMatched)
			{
				blockItems[aIdx][bIdx] = itemByCabbages[aIdx][bIdx];
			}
			if (blockItems[aIdx][bIdx].bMatched)
			{
				printf("%d ", blockItems[aIdx][bIdx].type);
			}
		}
		printf("\n");
	}
	//验证通过,算出一个路径出来
	std::deque<DATA_S> linkPath;
	re = LinkPathGen(blockItems[0], targetType, bMostlySearch, linkPath, sign, debug);
	if (-1 == re)
	{
		printf("LinkPathGen fail.\n");
		cv::imwrite(namesrc, src);
		cv::imwrite(namedrawsrc, calDrawSrc);
		return -1;
	}
	targetMatchCnt = re;
	for (int aIdx = 0; aIdx < linkPath.size(); aIdx++)
	{
		printf("[%d,%d]->", linkPath[aIdx].x, linkPath[aIdx].y);
	}
	printf("\n");
	////按路径划动
	if (3 != linkPath.size())
	{
		printf("3 != linkPath.size()\n");
		return -1;
	}

	if (!debug)
	{
		//按下移动
		dut->motionMoveStart(
			blockItems[linkPath[0].x][linkPath[0].y].pt.cx,
			blockItems[linkPath[0].x][linkPath[0].y].pt.cy,

			blockItems[linkPath[1].x][linkPath[1].y].pt.cx,
			blockItems[linkPath[1].x][linkPath[1].y].pt.cy,

			blockItems[linkPath[2].x][linkPath[2].y].pt.cx,
			blockItems[linkPath[2].x][linkPath[2].y].pt.cy
		);
	}

	if (bIncomeMax)
	{
		int doCnt = 1;
		do
		{
			int buffTime = 7; //简单路径留个7s,复杂路径留个12s,太慢太慢了,有点受不了
			if (targetMatchCnt > 3)
			{
				buffTime = 12;
			}
			int endTime = adventureEndTime(src, sign);
			if (-1 == endTime)
			{
				printf("endTime detech fail.\n");
				continue;
			}
			if (endTime > buffTime)
			{
				int sle = (endTime - buffTime) * 1000;   //如果是复杂的路径,分析就得需要点时间
				if (sle > 30 * 1000)
				{
					printf("fuck time\n");
					break;
				}
				printf("Sleep %d ms\n", sle);
				Sleep(sle);
				break;
			}
			doCnt--;
		} while (doCnt >= 0);
	}
	if (!debug)
	{
		//抬起
		dut->motionMoveEnd(
			blockItems[linkPath[2].x][linkPath[2].y].pt.cx,
			blockItems[linkPath[2].x][linkPath[2].y].pt.cy
		);
	}
	Sleep(1000);//1秒给手机反应去刷新界面
	return 0;
}

int Motion::pointSuccessLeave(const cv::Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/pointSuccess/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/pointSuccess/%d_drawsrc.jpg", sign);

	cv::Mat orangeMask;
	detectHSColor(src, 7, 13, 176, 249, orangeMask);
	cv::Mat reBtnSrc;
	src.copyTo(reBtnSrc, orangeMask);
	/*namedWindow("reBtnSrc", WINDOW_NORMAL);
	imshow("reBtnSrc", reBtnSrc);*/

	cv::Mat reBtnErodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(7, 7));
	Mat reBtnErodeSrc;
	cv::erode(reBtnSrc, reBtnErodeSrc, reBtnErodeEle);
	/*namedWindow("reBtnErodeSrc", WINDOW_NORMAL);
	imshow("reBtnErodeSrc", reBtnErodeSrc);*/

	cv::Mat reBtnDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(15, 15));
	Mat reBtnDilateSrc;
	cv::dilate(reBtnErodeSrc, reBtnDilateSrc, reBtnDilateEle);
	/*namedWindow("reBtnDilateSrc", WINDOW_NORMAL);
	imshow("reBtnDilateSrc", reBtnDilateSrc);*/

	cv::Mat reBtnGraySrc;
	cv::cvtColor(reBtnDilateSrc, reBtnGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("reBtnGraySrc", WINDOW_NORMAL);
	imshow("reBtnGraySrc", reBtnGraySrc);*/

	Mat reBtnBinSrc;
	cv::threshold(reBtnGraySrc, reBtnBinSrc, 0, 127, THRESH_BINARY);
	/*namedWindow("reBtnBinSrc", WINDOW_NORMAL);
	imshow("reBtnBinSrc", reBtnBinSrc);*/

	std::vector<std::vector<Point>> reBtnContours;
	std::vector<Vec4i> reBtnHi;
	cv::findContours(reBtnBinSrc, reBtnContours, reBtnHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	double maxArch = 0;
	int archIdx = -1;
	for (int aIdx = 0; aIdx < reBtnContours.size(); aIdx++)
	{
		double length = arcLength(reBtnContours[aIdx], 0);
		//printf("\t i:%d,reBtnArcLength:%1f\n", aIdx, length);
		if (length > maxArch)
		{
			maxArch = length;
			archIdx = aIdx;
		}
	}
	if (-1 == archIdx)
	{
		printf("success reBtn arch -1\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	Rect reBtnRec = boundingRect(reBtnContours[archIdx]);
	cv::Mat reBtnDrawSrc;
	src.copyTo(reBtnDrawSrc);
	auto M = moments(reBtnContours[archIdx]);
	int cx = int(M.m10 / M.m00);
	int cy = int(M.m01 / M.m00);
	//drawContours(reBtnDrawSrc, reBtnContours, archIdx, Scalar(255, 0, 0), 3);
	rectangle(reBtnDrawSrc, reBtnRec, Scalar(255, 0, 0), 3);
	//namedWindow("reBtnDrawSrc", WINDOW_NORMAL);
	//imshow("reBtnDrawSrc", reBtnDrawSrc);
	//waitKey(0);
	//这个矩形需要平行,且重心落在一定范围,352,1565
	//printf("%d:successfulBtnCxCy:[%d,%d]\n", sign, cx, cy);
	//successfulBtnCxCy:[352,1324]
	if (cx >= 350 && cx <= 354 && cy >= 1322 && cy <= 1326)
	{
		printf("%d:successful btn matched\n", sign);
		if (!debug)
		{
			dut->btnPress(cx, cy);
		}
		return 0;
	}
	cv::imwrite(namesrc, src);
	cv::imwrite(namedrawsrc, reBtnDrawSrc);
	return -1;
}

int Motion::pointFailLeave(const cv::Mat& src, int sign, bool debug)
{
	char namesrc[100] = { 0 };
	char namedrawsrc[100] = { 0 };
	sprintf_s(namesrc, 100, "Pic/pointFail/%d_src.jpg", sign);
	sprintf_s(namedrawsrc, 100, "Pic/pointFail/%d_drawsrc.jpg", sign);

	cv::Mat orangeMask;
	detectHSColor(src, 19, 24, 220, 244, orangeMask);
	cv::Mat reBtnSrc;
	src.copyTo(reBtnSrc, orangeMask);
	/*namedWindow("reBtnSrc", WINDOW_NORMAL);
	imshow("reBtnSrc", reBtnSrc);*/

	cv::Mat reBtnErodeEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(5, 5));
	Mat reBtnErodeSrc;
	cv::erode(reBtnSrc, reBtnErodeSrc, reBtnErodeEle);
	/*namedWindow("reBtnErodeSrc", WINDOW_NORMAL);
	imshow("reBtnErodeSrc", reBtnErodeSrc);*/

	cv::Mat reBtnDilateEle = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(15, 15));
	Mat reBtnDilateSrc;
	cv::dilate(reBtnErodeSrc, reBtnDilateSrc, reBtnDilateEle);
	/*namedWindow("reBtnDilateSrc", WINDOW_NORMAL);
	imshow("reBtnDilateSrc", reBtnDilateSrc);*/

	cv::Mat reBtnGraySrc;
	cv::cvtColor(reBtnDilateSrc, reBtnGraySrc, COLOR_BGR2GRAY);
	/*namedWindow("reBtnGraySrc", WINDOW_NORMAL);
	imshow("reBtnGraySrc", reBtnGraySrc);*/

	Mat reBtnBinSrc;
	cv::threshold(reBtnGraySrc, reBtnBinSrc, 0, 127, THRESH_BINARY);
	/*namedWindow("reBtnBinSrc", WINDOW_NORMAL);
	imshow("reBtnBinSrc", reBtnBinSrc);*/

	std::vector<std::vector<Point>> reBtnContours;
	std::vector<Vec4i> reBtnHi;
	cv::findContours(reBtnBinSrc, reBtnContours, reBtnHi, RETR_LIST, CHAIN_APPROX_SIMPLE);
	double maxArch = 0;
	int archIdx = -1;
	for (int aIdx = 0; aIdx < reBtnContours.size(); aIdx++)
	{
		double length = arcLength(reBtnContours[aIdx], 0);
		//printf("\t i:%d,reBtnArcLength:%1f\n", aIdx, length);
		if (length > maxArch)
		{
			maxArch = length;
			archIdx = aIdx;
		}
	}
	if (-1 == archIdx)
	{
		printf("fail reBtn arch -1\n");
		cv::imwrite(namesrc, src);
		return -1;
	}
	Rect reBtnRec = boundingRect(reBtnContours[archIdx]);
	cv::Mat reBtnDrawSrc;
	src.copyTo(reBtnDrawSrc);
	auto M = moments(reBtnContours[archIdx]);
	int cx = int(M.m10 / M.m00);
	int cy = int(M.m01 / M.m00);
	//drawContours(reBtnDrawSrc, reBtnContours, archIdx, Scalar(255, 0, 0), 3);
	rectangle(reBtnDrawSrc, reBtnRec, Scalar(255, 0, 0), 3);
	/*namedWindow("reBtnDrawSrc", WINDOW_NORMAL);
	imshow("reBtnDrawSrc", reBtnDrawSrc);
	waitKey(0);*/
	//printf("%d:failBtnCxCy:[%d,%d]\n", sign, cx, cy);
	//failBtnCxCy:[539,1252]
	if (cx >= 537 && cx <= 541 && cy >= 1250 && cy <= 1254)
	{
		printf("%d:fail btn matched\n", sign);
		if (!debug)
		{
			dut->btnPress(cx, cy);
		}
		return 0;
	}
	cv::imwrite(namesrc, src);
	cv::imwrite(namedrawsrc, reBtnDrawSrc);
	return -1;
}

Menu::Menu(bool bSmallScreen, std::string gUuid, bool gB_Shrink, int gDoCnt)
{
	uuid = gUuid;
	doCnt = gDoCnt;

	int ax = bx;
	int ay = by;
	int aw = bw;
	int ah = bh;

	if (bSmallScreen)
	{
		ax = sx;
		ay = sy;
		aw = sw;
		ah = sh;
	}
	if (gB_Shrink)
	{
		//设置了缩放,那scrcpy也要缩放
		ah = shrinkBh;
	}

	dut = new Scrcpy(uuid, gB_Shrink);   //设备有可能需要缩放
	motion = new Motion((Dut*)dut); 
	//配置dut
	dut->fpsPrintSet(true);
	dut->borderLessSet(true);
	dut->screenOffIfExitSet(true);
	dut->screenOffSet(true);
	dut->stayAwakSet(true);
	dut->topAlwaysSet(true);
	dut->positionX_Set(true, ax);
	dut->positionY_Set(true, ay);
	dut->widthSet(true, aw);
	dut->heightSet(true, ah);
	
	//执行启用Scrcpy.exe的操作
	if (-1 == dut->startUp())
	{
		printf("startUp fail\n");
		return;
	};

	//DutShot screenshot((Dut*)dut);
	//screenshot=new DutFasterShot((Dut*)dut);
	screenshot=new DutMiniShot((Dut*)dut);
	motion->PicDirectoryGen("Pic");
	motion->PicDirectoryGen("Pic\\gameStart");
	motion->PicDirectoryGen("Pic\\welcome");
	motion->PicDirectoryGen("Pic\\dailyLanding");
	motion->PicDirectoryGen("Pic\\checkPoints");
	motion->PicDirectoryGen("Pic\\pointEnter");
	motion->PicDirectoryGen("Pic\\adventure");
	motion->PicDirectoryGen("Pic\\endCnt");
	motion->PicDirectoryGen("Pic\\endStep");
	motion->PicDirectoryGen("Pic\\endTime");
	motion->PicDirectoryGen("Pic\\pointSuccess");
	motion->PicDirectoryGen("Pic\\pointFail");

	if (menuName.size() != menuFs.size())
	{
		perror("menuName.size() != menuFs.size()\n");
	}
}

Menu::~Menu()
{
	if (NULL != dut)
	{
		delete dut;
		dut = NULL;
	}
	
	if (NULL != screenshot)
	{
		delete screenshot;
		screenshot = NULL;
	}
	
	if (NULL != motion)
	{
		delete motion;
		motion = NULL;
	}
}

int Menu::help()
{
	for (int aIdx = 0; aIdx < menuName.size(); aIdx++)
	{
		printf("%d.%s\n", aIdx, menuName[aIdx].c_str());
	}
	printf("\n");
	return 0;
}

int Menu::setParams()
{
	int key = -1;
	printf("bSmallScreen 1 or 0?\n");
	(void)scanf_s("%d", &key);
	int ax = bx;
	int ay = by;
	int aw = bw;
	int ah = bh;
	if (1 == key)
	{
		ax = sx;
		ay = sy;
		aw = sw;
		ah = sh;
	}
	if (dut->bShrink) //设置了缩放,那scrcpy也要缩放
	{
		ah = shrinkBh;
	}
	dut->positionX_Set(true, ax);
	dut->positionY_Set(true, ay);
	dut->widthSet(true, aw);
	dut->heightSet(true, ah);

	printf("uuid\n");
	char buf[100] = { 0 };
	scanf_s("%s", buf, 100);
	uuid = std::string(buf);

	printf("doCnt\n");
	key = -1;
	(void)scanf_s("%d", &key);
	if (key > 0)
	{
		doCnt = key;
	}
	return 0;
}

int Menu::dutWmSizeShow()
{
	std::string cmd = "adb.exe -s " + dut->uuid + " shell \"wm size\"";
	std::string pipe_data;
	int re = dut->AdbCmd(cmd, pipe_data, 20000);
	printf("%s\n", pipe_data.c_str());
	return re;
}

int Menu::dutWmSizeSet()
{
	std::string cmd = "adb.exe -s " + dut->uuid + " shell \"wm size 1080x1920 && echo $?\"";
	std::string pipe_data;
	int re = dut->AdbCmd(cmd, pipe_data, 20000);
	printf("res:%s\n", pipe_data.c_str());
	if (std::string::npos != pipe_data.find("error"))
	{
		re = dut->uuidConnect();
		if (0 != re)
		{
			printf("uuidConnect again fail\n");
			return -1;
		}
	}
	dut->bShrink = true;
	//设置了缩放,那scrcpy也要缩放
	dut->heightSet(true, shrinkBh);
	return re;
}

int Menu::dutWmSizeReSet()
{
	std::string cmd = "adb.exe -s " + dut->uuid + " shell \"wm size reset && echo $?\"";
	std::string pipe_data;
	int re = dut->AdbCmd(cmd, pipe_data, 20000);
	printf("res:%s\n", pipe_data.c_str());
	if (std::string::npos != pipe_data.find("error"))
	{
		re = dut->uuidConnect();
		if (0 != re)
		{
			printf("uuidConnect again fail\n");
			return -1;
		}
	}
	dut->bShrink = false;
	//设置了缩放,那scrcpy也要缩放
	dut->heightSet(true, bh);
	return re;
}

int Menu::resumeAdb()
{
	Scrcpy* nDut = new Scrcpy((Scrcpy*)dut,dut->bShrink);
	dut->disposing();     
	nDut->startUp();
	dut = nDut;      //偷梁换柱
	printf("wtf\n");
	return 0;
}

int Menu::connect()
{
	dut->uuidConnect();
	return 0;
}

int Menu::exit()
{
	int re= (int)menuFs.size();
	return re;
}

int Menu::list()
{
	help();
	int key=-1;
	while (!_kbhit())  //没有输入,就等待
	{
		Sleep(100);
	}
	(void)scanf_s("%d", &key);
	(void)getchar();/*吃掉回车*/
	if (key< 0 || key>menuFs.size())
	{
		printf("key valid!\n");
		return -1;
	}
	printf("key==%d,%s\n", key, menuName[key].c_str());
	int re = -1;
	if (NULL != menuFs[key])
	{
		re=(this->*menuFs[key])();   //*==解引用
	}
	return re;
}

int Menu::gameStartRun()
{
	bool bTarget = false;
	char key = 0;
	bool bExit = false;
	for (int aIdx = 0; aIdx < 1000; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }

		Mat gameStartMat = screenshot->screenShotGet();
		if (gameStartMat.empty())
		{
			continue;
		};
		printf("%d:gameStartMat:[%d,%d]\n", aIdx, gameStartMat.cols, gameStartMat.rows);
		if (0 == motion->gameStartRun(gameStartMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到绿色按钮.\n");
		return -1;
	}
	return 0;
}

int Menu::welcomeRun()
{
	//欢迎页面
	bool bTarget = false;
	char key = 0;
	bool bExit = false;
	for (int aIdx = 0; aIdx < 3; aIdx++)  //因为拿图太慢,现在只拿5次
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat welcomeMat = screenshot->screenShotGet();
		if (welcomeMat.empty())
		{
			continue;
		};
		printf("%d:welcomeMat:[%d,%d]\n", aIdx, welcomeMat.cols, welcomeMat.rows);
		if (0 == motion->welcomeRun(welcomeMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到欢迎页面.\n");
	}
	return 0;
}

int Menu::dailyLandingRun()
{
	//每日登陆页面
	bool bTarget = false;
	char key = 0;
	bool bExit = false;
	for (int aIdx = 0; aIdx < 5; aIdx++)  //拿图太慢,现在只拿5次
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat dailyLandingMat = screenshot->screenShotGet();
		if (dailyLandingMat.empty()) { continue; };
		printf("%d:dailyLandingMat:[%d,%d]\n", aIdx, dailyLandingMat.cols, dailyLandingMat.rows);
		if (0 == motion->dailyLandingRun(dailyLandingMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到每日登陆页面.\n");
		return -1;
	}
	return 0;
}

int Menu::checkPointsRun()
{
	//关卡页面
	char key = 0;
	bool bExit = false;
	bool bTarget = false;
	for (int aIdx = 0; aIdx < 30; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat checkPointsMat = screenshot->screenShotGet();
		if (checkPointsMat.empty()) { continue; };
		printf("%d:checkPointsMat:[%d,%d]\n", aIdx, checkPointsMat.cols, checkPointsMat.rows);
		if (0 == motion->checkPointsRun(checkPointsMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到关卡页面.\n");
		return -1;
	}
	return 0;
}

int Menu::pointEnter()
{
	//第1关的进入页面
	char key = 0;
	bool bExit = false;
	bool bTarget = false;
	for (int aIdx = 0; aIdx < 3; aIdx++)   //拿图太慢,只看3次
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat onePointMat = screenshot->screenShotGet();
		if (onePointMat.empty()) { continue; };
		printf("%d:onePointMat:[%d,%d]\n", aIdx, onePointMat.cols, onePointMat.rows);
		if (0 == motion->pointEnter(onePointMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到第1关的进入页面.\n");
		return -1;
	}
	return 0;
}

int Menu::idleOp()
{
	motion->idleOp(0, true);
	return 0;
}

int Menu::adventureEndStep()
{
	int endStep = -1;
	char key = 0;
	bool bExit = false;
	int targetEndStep = 8;  //目标步数
	for (int aIdx = 0; aIdx < 30; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat endStepMat;
		motion->idleOp(aIdx, true);    //有idle
		endStepMat = screenshot->screenShotGet();
		if (endStepMat.empty()) { continue; };
		printf("%d:endStepMat:[%d,%d]\n", aIdx, endStepMat.cols, endStepMat.rows);
		endStep = motion->adventureEndStep(endStepMat, aIdx);
		if (-1 == endStep)
		{
			printf("endStep detech fail.\n");
			continue;
		}
		break;
	}
	if (-1 == endStep || targetEndStep != endStep)
	{
		return -1;
	}
	return 0;
}

int Menu::adventureEndCnt()
{
	char key = 0;
	bool bExit = false;
	int endCnt = -1;
	for (int aIdx = 0; aIdx < 30; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat endCntMat = screenshot->screenShotGet();
		if (endCntMat.empty()) { continue; };
		printf("%d:endCntMat:[%d,%d]\n", aIdx, endCntMat.cols, endCntMat.rows);
		endCnt = motion->adventureEndCnt(endCntMat, aIdx);
		if (-1 == endCnt)
		{
			printf("endCnt detech fail.\n");
			continue;
		}
		break;
	}
	if (-1 == endCnt)
	{
		return -1;
	}
	return 0;
}

int Menu::adventureEndTime()
{
	char key = 0;
	bool bExit = false;
	int endTime = -1;
	for (int aIdx = 0; aIdx < 30; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }
		Mat endTimeMat = screenshot->screenShotGet();
		if (endTimeMat.empty()) { continue; };
		printf("%d:endTimeMat:[%d,%d]\n", aIdx, endTimeMat.cols, endTimeMat.rows);
		endTime = motion->adventureEndTime(endTimeMat, aIdx);
		if (-1 == endTime)
		{
			printf("endTime detech fail.\n");
			continue;
		}
		break;
	}
	if (-1 == endTime)
	{
		return -1;
	}
	return 0;
}

int Menu::adventureRun()
{
	const bool bIncomeMax = false;
	const bool bMostlySearch = false;
	Motion::itemType_e itemType;

	Mat sudoMat;
	motion->idleOp(0, true);  //截图太慢了,会有干扰出现,截图前加个idle
	sudoMat = screenshot->screenShotGet();
	if (sudoMat.empty()) 
	{ 
		printf("sudoMat.empty\n");
		return -1;
	};
	printf("i==%d,sudoMat==%d,%d\n", 0, sudoMat.cols, sudoMat.rows);

	itemType = Motion::cabbage_e;    //这个是变量?
	int targetMatchCnt = -1;
	int re = motion->adventureRun(sudoMat, itemType, bIncomeMax, bMostlySearch, targetMatchCnt, 0);
	return 0;
}

int Menu::pointSuccessLeave()
{
	Mat resultMat = screenshot->screenShotGet();
	if (resultMat.empty())
	{
		printf("resultMat.empty\n");
		return -1;
	};
	printf("%d:resultMat:[%d,%d]\n", 0, resultMat.cols, resultMat.rows);
	if (0 == motion->pointSuccessLeave(resultMat, 0))
	{
		
	}
	return -1;
}

int Menu::pointFailLeave()
{
	Mat resultMat = screenshot->screenShotGet();
	if (resultMat.empty())
	{
		printf("resultMat.empty\n");
		return -1;
	};
	printf("%d:resultMat:[%d,%d]\n", 0, resultMat.cols, resultMat.rows);
	if (0 == motion->pointFailLeave(resultMat, 0))
	{
		
	}
	return -1;
}

int Menu::savePng()
{
	char key = 0;
	bool bExit = false;
	for (int aIdx = 0; aIdx < 10000; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }

		cv::Mat dutMat = screenshot->screenShotGet();
		if (false == dutMat.empty())
		{
			char tmp[MAX_PATH] = { 0 };
			sprintf_s(tmp, MAX_PATH, "Pic/%d_src.png", aIdx);
			cv::imwrite(tmp, dutMat);
		}
	}
	printf("出循环了\n");
	getchar();
	return 0;

	/*for (size_t aIdx = 0; aIdx < 10000; aIdx++)
	{
		Mat img_ = screenshot.screenShotGet(ax, ay, aw, ah);
		char temp[512] = { 0 };
		sprintf_s(temp, 512, "Pic/z%d.jpg", aIdx);
		imwrite(temp, img_);
		Sleep(500);
	}*/
	return 0;
}

int Menu::saveJpg()
{
	char key = 0;
	bool bExit = false;
	for (int aIdx = 0; aIdx < 10000; aIdx++)
	{
		while (_kbhit())
		{
			key = _getch();
			printf("key2==%c\n", key);
			if ('q' == key)
			{
				bExit = true;
				break;
			}
		}
		if (bExit) { break; }

		cv::Mat dutMat = screenshot->screenShotGet();
		if (false == dutMat.empty())
		{
			char tmp[MAX_PATH] = { 0 };
			sprintf_s(tmp, MAX_PATH, "Pic/%d_src.jpg", aIdx);
			cv::imwrite(tmp, dutMat);
		}
	}
	printf("出循环了\n");
	getchar();
	return 0;
}

int Menu::autoRun()
{
	bool bTarget = false;
	for (int aIdx = 0; aIdx < 1000; aIdx++)
	{
		Mat gameStartMat = screenshot->screenShotGet();
		if (gameStartMat.empty())
		{
			continue;
		};
		printf("%d:gameStartMat:[%d,%d]\n", aIdx, gameStartMat.cols, gameStartMat.rows);
		if (0 == motion->gameStartRun(gameStartMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到绿色按钮.\n");
		return -1;
	}

	//欢迎页面
	bTarget = false;
	for (int aIdx = 0; aIdx < 8; aIdx++)  //因为拿图太慢,现在只拿8次
	{
		Mat welcomeMat = screenshot->screenShotGet();
		if (welcomeMat.empty())
		{
			continue;
		};
		printf("%d:welcomeMat:[%d,%d]\n", aIdx, welcomeMat.cols, welcomeMat.rows);
		if (0 == motion->welcomeRun(welcomeMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到欢迎页面.\n");
	}

	//每日登陆页面
	bTarget = false;
	for (int aIdx = 0; aIdx < 5; aIdx++)  //拿图太慢,现在只拿5次
	{
		Mat dailyLandingMat = screenshot->screenShotGet();
		if (dailyLandingMat.empty()) { continue; };
		printf("%d:dailyLandingMat:[%d,%d]\n", aIdx, dailyLandingMat.cols, dailyLandingMat.rows);
		if (0 == motion->dailyLandingRun(dailyLandingMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到每日登陆页面.\n");
		return -1;
	}
	//关卡页面
	bTarget = false;
	for (int aIdx = 0; aIdx < 30; aIdx++)
	{
		Mat checkPointsMat = screenshot->screenShotGet();
		if (checkPointsMat.empty()) { continue; };
		printf("%d:checkPointsMat:[%d,%d]\n", aIdx, checkPointsMat.cols, checkPointsMat.rows);
		if (0 == motion->checkPointsRun(checkPointsMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到关卡页面.\n");
		return -1;
	}

	//第1关的进入页面
	bTarget = false;
	for (int aIdx = 0; aIdx < 3; aIdx++)   //拿图太慢,只看3次
	{
		Mat onePointMat = screenshot->screenShotGet();
		if (onePointMat.empty()) { continue; };
		printf("%d:onePointMat:[%d,%d]\n", aIdx, onePointMat.cols, onePointMat.rows);
		if (0 == motion->pointEnter(onePointMat, aIdx))
		{
			bTarget = true;
			break;
		}
	}
	if (!bTarget)
	{
		printf("找不到第1关的进入页面.\n");
		return -1;
	}

	int endCnt = -1;
	int endStep = -1;
	int endTime = -1;
	int targetEndStep = 8;  //目标步数
	//当endCnt拿得到的时候,endStep/endTime也能拿了
	for (int aIdx = 0; aIdx < 30; aIdx++)
	{
		Mat mixMat = screenshot->screenShotGet();
		if (mixMat.empty()) { continue; };
		printf("%d:mixMat:[%d,%d]\n", aIdx, mixMat.cols, mixMat.rows);
		if (-1 == endCnt)   //没拿到endCnt
		{
			endCnt = motion->adventureEndCnt(mixMat, aIdx);
			if (-1 == endCnt)
			{
				printf("endCnt detech fail.\n");
				continue;
			}
		}
		if (-1 == endStep)  //没拿到步数
		{
			endStep = motion->adventureEndStep(mixMat, aIdx);
			if (-1 == endStep)
			{
				printf("endStep detech fail.\n");
				continue;
			}
		}
		
		endTime = motion->adventureEndTime(mixMat, aIdx);
		if (-1 == endTime)
		{
			printf("endTime detech fail.\n");
			continue;
		}
		break;
	}
	if (-1 == endCnt||-1== endStep|| targetEndStep != endStep)
	{
		return -1;
	}

	char key = 0;
	bool bExit = false;
	do
	{
		doCnt--;
		bool bGameSuccess = false;
		//第1关的sudo
		for (int aIdx = 0; aIdx < 35; aIdx++)
		{
			while (_kbhit())
			{
				key = _getch();
				printf("key2==%c\n", key);
				if ('q' == key)
				{
					bExit = true;
					break;
				}
			}
			if (bExit) { break; }
			Mat sudoMat;
			motion->idleOp(aIdx, true);  //截图太慢了,会有干扰出现,截图前加个idle
			sudoMat = screenshot->screenShotGet();
			if (sudoMat.empty()) { continue; };
			printf("i==%d,sudoMat==%d,%d,endCnt==%d,endStep==%d\n", aIdx, sudoMat.cols, sudoMat.rows, endCnt, endStep);
			int re = -1;
			//先连一个cabbage,再连6次白萝卜,最后连一个cabbage
			int targetMatchCnt = -1;
			Motion::itemType_e itemType;
			bool bMostlySearch;
			if (8 == endStep || 1 == endStep)
			{
				itemType = Motion::cabbage_e;
				bMostlySearch = false;
				re = motion->adventureRun(sudoMat, itemType, false, bMostlySearch, targetMatchCnt, aIdx);
			}
			else
			{
				itemType = Motion::moli_e;
				bMostlySearch = false;   //会撞击出很多小星星,所以要判断一下是否已经通关了?没收益,不做了
				re = motion->adventureRun(sudoMat, itemType, false, bMostlySearch, targetMatchCnt, aIdx);
			}
			while (_kbhit())
			{
				key = _getch();
				printf("key2==%c\n", key);
				if ('q' == key)
				{
					bExit = true;
					break;
				}
			}
			if (bExit) { break; }
			if (0 == re)
			{
				//判断是否完成界面了
				targetEndStep--;
				for (int bIdx = 0; bIdx < 5; bIdx++)
				{
					while (_kbhit())
					{
						key = _getch();
						printf("key2==%c\n", key);
						if ('q' == key)
						{
							bExit = true;
							break;
						}
					}
					if (bExit) { break; }
					if (0 == targetEndStep)  //要找的是0,即通关了,还有识别已经手动屏蔽了0了
					{
						printf("0 == targetEndStep,game over\n");
						bGameSuccess = true;
						break;
					}
					sudoMat = screenshot->screenShotGet();
					if (sudoMat.empty()) { continue; }; //重新截图
					int tmpEndStep = motion->adventureEndStep(sudoMat, bIdx);
					if (-1 != tmpEndStep && tmpEndStep == targetEndStep)   //垃圾字体,1识别成l还有识别成7了
					{
						endStep = tmpEndStep;
						break;
					}
					printf("%d:targetEndStep:%d==tmpEndStep:%d fail.\n", bIdx, targetEndStep, tmpEndStep);
				}//for
				if (bExit) { break; }

				//因为1会被识别成7,所以做下判断
				if (1 == targetEndStep && 1 != endStep)
				{
					endStep = 1;
					printf("modify endStep=1\n");
				}

				if (0 == endStep)
				{
					//判断成功还是失败
					break;
				}
				if (bGameSuccess)
				{
					break;
				}
			}//游戏for循环
		}//第1关的sudo for循环
		if (bExit) { break; }

		//结果判断
		int mode = -1;
		for (int aIdx = 0; aIdx < 10; aIdx++)
		{
			while (_kbhit())
			{
				key = _getch();
				printf("key2==%c\n", key);
				if ('q' == key)
				{
					bExit = true;
					break;
				}
			}
			if (bExit) { break; }
			Mat resultMat = screenshot->screenShotGet();
			if (resultMat.empty()) { continue; };
			printf("%d:resultMat:[%d,%d]\n", aIdx, resultMat.cols, resultMat.rows);
			if (0 == motion->pointSuccessLeave(resultMat, aIdx))
			{
				mode = 0;
				targetEndStep = 8;  //要等到他刷新完页面再往下走
				for (int bIdx = 0; bIdx < 10; bIdx++)
				{
					Mat endStepMat = screenshot->screenShotGet();
					if (endStepMat.empty()) { continue; }; //重新截图
					int tmpEndStep = motion->adventureEndStep(endStepMat, bIdx);
					if (-1 != tmpEndStep && tmpEndStep == targetEndStep)   //垃圾字体,1识别成l还有识别成7了
					{
						endStep = tmpEndStep;
						break;
					}
					printf("%d:targetEndStep:%d==tmpEndStep:%d fail.\n", bIdx, targetEndStep, tmpEndStep);
				}
				break;
			}
			else if (0 == motion->pointFailLeave(resultMat, aIdx))
			{
				mode = 1;
				targetEndStep = 8;  //要等到他刷新完页面再往下走
				for (int bIdx = 0; bIdx < 10; bIdx++)
				{
					Mat endStepMat = screenshot->screenShotGet();
					if (endStepMat.empty()) { continue; }; //重新截图
					int tmpEndStep = motion->adventureEndStep(endStepMat, bIdx);
					if (-1 != tmpEndStep && tmpEndStep == targetEndStep)   //垃圾字体,1识别成l还有识别成7了
					{
						endStep = tmpEndStep;
						break;
					}
					printf("%d:targetEndStep:%d==tmpEndStep:%d fail.\n", bIdx, targetEndStep, tmpEndStep);
				}
				break;
			}
		}//for
		if (bExit) { break; }
		if (-1 == mode)
		{
			printf("找不到结算页面,doCnt==%d.\n", doCnt);
			return -1;
		}
		else if (0 == mode)
		{
			printf("成功了,doCnt==%d.\n", doCnt);
		}
		else if (1 == mode)
		{
			printf("失败了,doCnt==%d.\n", doCnt);
		}
	} while (doCnt > 0);
	printf("autoRun end.\n");
	//清空输入
	while (_kbhit())
	{
		(void)_getch();
	}
	return 0;
}

int main(int argc,char**argv)
{
	const bool bShrink = true;        //dut是否要收缩屏幕
	const bool bSmallScreen = true;  //电脑是大屏还是小屏
	std::string uuid = "192.168.10.250"; //32a5b74f  192.168.200.105
	if (argc > 1)
	{
		uuid = argv[1];
	}
	const int doCnt = 15;   //autoRun循环

	Menu* meu=new Menu(bSmallScreen,uuid, bShrink,doCnt);   //因为要及时释放ddddocr,所以这里用了new
	while (1)
	{
		if (meu->menuFs.size() == meu->list())  //列表的最后一个就是离开
		{
			break;
		};
	}
	delete meu;
	meu = NULL;

	Dut* dut = new Dut(uuid,bShrink);
	Motion motion((Dut*)dut);
	int aIdx = 0;
	for (aIdx = 54; aIdx < 55; aIdx++)
	{
		char tmp[MAX_PATH] = { 0 };
		sprintf_s(tmp, MAX_PATH, "Pic/a/%d_src.jpg", aIdx);
		Mat matGet = imread(tmp, IMREAD_UNCHANGED);
		if (matGet.empty())
		{
			printf("read matGet fail.\n");
			return -1;
		}
		int targetMatchCnt = -1;
		int re = motion.adventureRun(matGet, Motion::cabbage_e, false, false, targetMatchCnt, aIdx,true);
		if (0 == re)
		{
			printf("%d:成功\n", aIdx);
		}
	}
	//zlib弄成静态编译进去的样子
	//minitouch操作更快?
	(void)getchar();
	delete dut;
	dut = NULL;
	return 0;
}
