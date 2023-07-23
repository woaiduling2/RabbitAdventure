#pragma once
#include <chrono>
#include <Windows.h>
#include <opencv2/opencv.hpp>
#include <zlib.h>
#pragma warning(disable:26812)

extern std::string exePath;
extern std::string exePathGet();
extern char* WCharToChar(const WCHAR* lpszSrc, char* lpszDes, DWORD nBufLen);
extern WCHAR* CharToWChar(const char* lpszSrc, WCHAR* lpszDes, DWORD nBufLen);
unsigned __stdcall startUping(void* p);

static size_t get_page_size()
{
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    return sysInfo.dwPageSize;
}

const size_t page_size = get_page_size();

template <typename TElem>
requires std::is_trivial_v<TElem>
class single_page_buffer
{
    TElem* _ptr = nullptr;

public:
    single_page_buffer()
    {
        _ptr = reinterpret_cast<TElem*>(_aligned_malloc(page_size, page_size));
        if (!_ptr) throw std::bad_alloc();
    }

    explicit single_page_buffer(std::nullptr_t) {}

    ~single_page_buffer()
    {
        if (_ptr) _aligned_free(reinterpret_cast<void*>(_ptr));
    }

    // disable copy construct
    single_page_buffer(const single_page_buffer&) = delete;
    single_page_buffer& operator=(const single_page_buffer&) = delete;

    inline single_page_buffer(single_page_buffer&& other) noexcept { std::swap(_ptr, other._ptr); }
    inline single_page_buffer& operator=(single_page_buffer&& other) noexcept
    {
        if (_ptr)
        {
            _aligned_free(reinterpret_cast<void*>(_ptr));
            _ptr = nullptr;
        }
        std::swap(_ptr, other._ptr);
        return *this;
    }

    inline TElem* get() const { return _ptr; }
    inline size_t size() const { return _ptr ? (page_size / sizeof(TElem)) : 0; }
};

//来个经典的控制接口类,会有子类从这里派生,但是他能从父接口这里拿到想要的东西
class Ctl
{
public:
    Ctl();
    ~Ctl();
    Ctl(const Ctl&) = delete;  //把拷贝构造函数删了
    int AdbCmd(const std::string adbInput, const std::string matchOut/*需要命中目标才从while循环返回,或超过次数返回*/, const std::string sign, bool debug = false);
    int AdbCmd(const std::string& cmd, std::string& pipe_data,int64_t timeout);
private:
    bool CreateOverlappablePipe(HANDLE* read, HANDLE* write, SECURITY_ATTRIBUTES* secattr_read,
        SECURITY_ATTRIBUTES* secattr_write, DWORD bufsize, bool overlapped_read,
        bool overlapped_write);
};

class Dut:public Ctl    //这是手机控制类里的子类,即具体类
{
public:
    bool bShrink;//dut是否要收缩屏幕
    std::string uuid; //adb device出现的东西
    explicit Dut()=delete;
    explicit Dut(const std::string gUuid,bool gB_Shrink);
    ~Dut();
    virtual int startUp() { printf("startUp unSupport!\n"); return -1; };   //启动scrcpy
    int uuidConnect();
    int btnPress(int x, int y);
    int btnPress(int x, int y, int duration_ms/*单位:毫秒*/);
    int swipe(int sx, int sy, int ex, int ey, int duration_ms = 1000/*单位:毫秒*/, bool waitOff = false/*是否等待返回*/);
    int motionMoveStart(int x1, int y1, int x2, int y2, int x3, int y3);
    int motionMoveEnd(int x3, int y3);
    virtual void disposing() { printf("disposing unSupport!\n"); return; }; //资源释放
};

class Scrcpy:public Dut   //手机控制有个scrcpy去启动他来看到界面,这相当于是设备控制里的显示线程
{
public:
    bool bStartUp;
    PROCESS_INFORMATION* pi;
    HANDLE   hRead, hWrite;
    STARTUPINFO   si;
    bool bStayAwak;  //turn screen off and stay awake 
    bool bScreenOff; //turn-screen-off
    bool bFpsPrint;  //是否打印fps数据
    bool bPositionX; //是否指定窗口x坐标
    bool bPositionY; //是否指定窗口y坐标
    bool bTopAlways; //是否置顶窗口
    bool bScreenOffIfExit; //关闭scrcpy时是否灭屏
    bool bBorderLess;//是否无边框显示
    bool bWidth;     //是否设置窗口宽度
    bool bHeight;    //是否设置窗口高度
    int positionX;
    int positionY;
    int scrcpyW;
    int scrcpyH;
    explicit Scrcpy()=delete;
    explicit Scrcpy(const std::string gUuid,bool gB_Shrink);
    explicit Scrcpy(const Scrcpy* one, bool gB_Shrink):Dut(one->uuid, gB_Shrink)   //拷贝构造函数
    {
        bStayAwak = one->bStayAwak;
        bScreenOff = one->bScreenOff;
        bFpsPrint = one->bFpsPrint;
        bPositionX = one->bPositionX;
        bPositionY = one->bPositionY;
        bTopAlways = one->bTopAlways;
        bScreenOffIfExit = one->bScreenOffIfExit;
        bBorderLess = one->bBorderLess;
        bWidth = one->bWidth;
        bHeight = one->bHeight;
        positionX = one->positionX;
        positionY = one->positionY;
        scrcpyW = one->scrcpyW;
        scrcpyH = one->scrcpyH;
        
        bStartUp = false;
        handle = 0;
        hRead = 0;
        hWrite = 0;
        ::memset(&si, 0, sizeof(si));
        pi = new PROCESS_INFORMATION();
    }
    ~Scrcpy();
    virtual int startUp() override;
    virtual void disposing()override; //可以主动调用资源释放

    int stayAwakSet(bool enable);
    int screenOffSet(bool enable);
    int fpsPrintSet(bool enable);
    int topAlwaysSet(bool enable);
    int screenOffIfExitSet(bool enable);
    int borderLessSet(bool enable);
    int positionX_Set(bool enable, int x = 1800);
    int positionY_Set(bool enable, int y = 50);
    int widthSet(bool enable, int w = 600);
    int heightSet(bool enable, int h = 1330);
private:
    HANDLE handle;
};

//屏幕截图的来源是设备,可能是DUT也可能是电脑,或是电脑上的模拟器
//来自DUT那就是说利用的adb控制,需要有adb的控制,还有能访问uuid
//来自电脑,说明用的是屏幕载图的方式,需要知道屏幕的缩放比
//对外,别人不想知道你是从哪来的图片,他想依赖什么,全部从这个截图类得到
class Screenshot   //这是图片控制类的子类,即识别的输入
{
public:
    explicit Screenshot();
    //其实别人不想知道你是adb拿的截图还是pc拿的截图,他只是想拿到截图,他有什么错?
    virtual cv::Mat screenShotGet() { printf("screenShotGet unSupport\n"); return cv::Mat(); };
    virtual cv::Mat screenShotGet(int x, int y, int width, int height) { printf("screenShotGet xywh unSupport\n"); return cv::Mat(); };
};

class PcShot :public Screenshot
{
public:
    double zoom;
    PcShot();
    ~PcShot();
    double zoomGet();         //获取屏幕缩放值
    virtual cv::Mat screenShotGet()override;  //获取整个屏幕的截图
    virtual cv::Mat screenShotGet(int x, int y, int width, int height)override;
private:
    int m_width;
    int m_height;
    HDC m_screenDC;
    HDC m_compatibleDC;
    HBITMAP m_hBitmap;
    LPVOID m_screenshotData = nullptr;
};

class DutShot:public Screenshot   //自己写的抓图,这里抓的是png
{
public:
    DutShot()=delete;
    DutShot(Dut* gDut);
    ~DutShot();
    virtual cv::Mat screenShotGet()override;
    int dutScreenShoetInPhone(bool debug);
    int dutScreenShoetPull(bool debug);
protected:
    Dut* dut;
};

class DutFasterShot:public DutShot  //别人写的抓图,这里抓的是png,(还可以压缩图片传输,效果不明显)
{
public:
    DutFasterShot()=delete;
    DutFasterShot(Dut* gDut);
    ~DutFasterShot();
    virtual cv::Mat screenShotGet()override;
private:
    const int m_width =  1080;   //手机宽高
    const int m_height = 2400;
    bool decode_raw_with_gzip;   //是否用gzip压缩图片
};

class DutMiniShot :public DutShot  //minicap抓jpg图,会指定长宽去抓,手机要与图片保持一致
{
public:
    DutMiniShot() = delete;
    DutMiniShot(Dut* gDut);
    ~DutMiniShot();
    virtual cv::Mat screenShotGet()override;
private:
};

//作一下识别,然后做一些动作
//得到任务,执行任务?
class Motion
{
public:
    typedef enum
    {
        item_null = 0,
        moli_e = 1,
        cabbage_e = 2,
    }itemType_e;
private:
    Dut* dut;
    bool idleDisable;
    typedef struct _DATA_S
    {
        int x;
        int y;
    }DATA_S;

    typedef struct
    {
        int ltx;  //左上x
        int lty;  //左上y
        int rbx;  //右下x
        int rby;  //右下y
        int cx;   //坐标点击依据
        int cy;   //坐标点击依据
    }point_s;      //sudo里的格子,是图像实际占用的大小与坐标信息

    typedef struct
    {
        point_s pt;
        bool bMatched; //是否命中了,默认是没命中
        itemType_e type;
    }blockItem_s;      //sudo中的方块结构体,基本覆盖完了整个sudo

    void detectHSColor(const cv::Mat& image, double minHue, double maxHue, double minSat, double maxSat, cv::Mat& mask);
public:
    Motion(Dut*);
    ~Motion();
    int gameStartRun(const cv::Mat& src,int sign,bool debug=false);       //进入游戏页面
    int welcomeRun(const cv::Mat& src, int sign,bool debug=false);        //欢迎回来的页面
    int dailyLandingRun(const cv::Mat& src, int sign,bool debug=false);   //每日登陆的页面
    int checkPointsRun(const cv::Mat& src,  int sign, int checkNum=1/*找到第一关*/, bool debug=false);  //关卡主页面,可拖动选择关卡
    int pointEnter(const cv::Mat& src, int sign,bool debug=false); //指定运行某关卡时，会弹个页面来提示需要什么条件
    int adventureRun(const cv::Mat& src, itemType_e targetType/*每次识别sudo后要连成3个的目标类型*/,bool bIncomeMax/*是否收益最大化*/,bool bMostlySearch,int& targetMatchCnt/*实际连起来的数量*/, int sign, bool debug = false);      //兔子冒险的主体,即主页面,后续的1关卡都是在这个页面上增加难度而已
    int pointSuccessLeave(const cv::Mat& src, int sign, bool debug = false); //成功时会弹出的页面
    int pointFailLeave(const cv::Mat& src, int sign, bool debug=false);    //失败时会弹出的页面
    int PicDirectoryGen(const char* dirName="Pic");
    int numRec(const cv::Mat& src, int sign); //识别关卡数
    std::string charRec(const cv::Mat& src, int sign); //识别字符
    int adventureEndCnt(const cv::Mat& src, int sign, bool debug = false);
    int adventureEndStep(const cv::Mat& src, int sign, bool debug = false);
    int adventureEndTime(const cv::Mat& src, int sign, bool debug = false);
    int adventureSudo(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& sudoWidth, int& sudoHeight,int sign, bool debug = false);
    int adventureItemsByMoli(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& sudoWidth, int& sudoHeight, int& blockWidth, int& blockHight, cv::Mat& calDrawSrc, blockItem_s* itemByMolis, int sign, bool debug=false);
    int adventureItemsByCabbage(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& blockWidth, int& blockHight, cv::Mat& calDrawSrc, blockItem_s* itemByCabbages,int sign, bool debug=false);
    int LinkPathGen(blockItem_s* blockItems, itemType_e type,bool bMostlySearch/*尽可能的搜索多的路径*/, std::deque<DATA_S>& linkPath, int sign, bool debug = false);
    void idleOp(int sign, bool bFaster/*不等待返回,即加快速度*/ = false, bool debug = false);
};

class Decompressor
{
    std::size_t max_;

public:
    Decompressor(std::size_t max_bytes = 1000000000) // by default refuse operation if compressed data is > 1GB
        : max_(max_bytes)
    {}

    template <typename OutputType>
    void decompress(OutputType& output, const char* data, std::size_t size) const
    {
        z_stream inflate_s;

        inflate_s.zalloc = Z_NULL;
        inflate_s.zfree = Z_NULL;
        inflate_s.opaque = Z_NULL;
        inflate_s.avail_in = 0;
        inflate_s.next_in = Z_NULL;

        // The windowBits parameter is the base two logarithm of the window size (the size of the history buffer).
        // It should be in the range 8..15 for this version of the library.
        // Larger values of this parameter result in better compression at the expense of memory usage.
        // This range of values also changes the decoding type:
        //  -8 to -15 for raw deflate
        //  8 to 15 for zlib
        // (8 to 15) + 16 for gzip
        // (8 to 15) + 32 to automatically detect gzip/zlib header
        //constexpr int window_bits = 15 + 32; // auto with windowbits of 15
        constexpr int window_bits = 15 + 32; // auto with windowbits of 15

        if (inflateInit2(&inflate_s, window_bits) != Z_OK)
        {
            throw std::runtime_error("inflate init failed");
        }
        inflate_s.next_in = reinterpret_cast<z_const Bytef*>(data);    //有问题

#ifdef DEBUG
        // Verify if size (long type) input will fit into unsigned int, type used for zlib's avail_in
        std::uint64_t size_64 = size * 2;
        if (size_64 > std::numeric_limits<unsigned int>::max())
        {
            inflateEnd(&inflate_s);
            throw std::runtime_error("size arg is too large to fit into unsigned int type x2");
        }
#endif
        if (size > max_ || (size * 2) > max_)
        {
            inflateEnd(&inflate_s);
            throw std::runtime_error("size may use more memory than intended when decompressing");
        }
        inflate_s.avail_in = static_cast<unsigned int>(size);
        std::size_t size_uncompressed = 0;
        do
        {
            std::size_t resize_to = size_uncompressed + 2 * size;
            if (resize_to > max_)
            {
                inflateEnd(&inflate_s);
                throw std::runtime_error(
                    "size of output string will use more memory then intended when decompressing");
            }
            output.resize(resize_to);
            inflate_s.avail_out = static_cast<unsigned int>(2 * size);
            inflate_s.next_out = reinterpret_cast<Bytef*>(&output[0] + size_uncompressed);
            int ret = inflate(&inflate_s, Z_FINISH);
            if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR)
            {
                std::string error_msg = inflate_s.msg;
                inflateEnd(&inflate_s);
                // throw std::runtime_error(error_msg);
                output.clear();
                return;
            }

            size_uncompressed += (2 * size - inflate_s.avail_out);
        } while (inflate_s.avail_out == 0);
        inflateEnd(&inflate_s);
        output.resize(size_uncompressed);
    }
};

inline std::string decompress(const char* data, std::size_t size)
{
    Decompressor decomp;
    std::string output;
    decomp.decompress(output, data, size);
    return output;
}

class Menu
{
public:
    typedef int(Menu::* MenuFp)();  //声明指向Menu的成员函数指针

    std::map<int, MenuFp> menuFs =   //定义
    {
        { 0,  NULL },       //因为menuName找不到就会有一个默认0,所以现在这里要跟着有个NULL
        { 1,  &Menu::autoRun },
        { 2,  &Menu::gameStartRun },
        { 3,  &Menu::welcomeRun },
        { 4,  &Menu::dailyLandingRun },
        { 5,  &Menu::checkPointsRun },
        { 6,  &Menu::pointEnter },
        { 7,  &Menu::idleOp },
        { 8,  &Menu::adventureEndStep },
        { 9,  &Menu::adventureEndCnt },
        { 10, &Menu::adventureEndTime },
        { 11, &Menu::adventureRun },
        { 12, &Menu::pointSuccessLeave },
        { 13, &Menu::pointFailLeave },
        { 14, &Menu::savePng },
        { 15, &Menu::saveJpg },
        { 16, &Menu::setParams },
        { 17, &Menu::dutWmSizeShow },
        { 18, &Menu::dutWmSizeSet },
        { 19, &Menu::dutWmSizeReSet },
        { 20, &Menu::resumeAdb },
        { 21, &Menu::connect },
        { 22, &Menu::exit },
    };
    std::map<int, std::string> menuName =   //函数名定义
    {
        { 0,  "nothing" },
        { 1,  "autoRun" },
        { 2,  "gameStartRun" },
        { 3,  "welcomeRun" },
        { 4,  "dailyLandingRun" },
        { 5,  "checkPointsRun" },
        { 6,  "pointEnter" },
        { 7,  "idleOp" },
        { 8,  "adventureEndStep" },
        { 9,  "adventureEndCnt" },
        { 10, "adventureEndTime" },
        { 11, "adventureRun" },
        { 12, "pointSuccessLeave" },
        { 13, "pointFailLeave" },
        { 14, "savePng" },
        { 15, "saveJpg" },
        { 16, "setParams" },
        { 17, "dutWmSizeShow" },
        { 18, "dutWmSizeSet" },
        { 19, "dutWmSizeReSet" },
        { 20, "resumeAdb" },
        { 21, "connect" },
        { 22, "exit" },
    };

    Menu()=delete;
    Menu(bool bSmallScreen/*电脑是大屏还是小屏*/,  std::string gUuid, bool gB_Shrink, int gDoCnt);
    ~Menu();
    int help();
    int list();
    int autoRun();
    int gameStartRun();
    int welcomeRun();
    int dailyLandingRun();
    int checkPointsRun();
    int pointEnter();
    int idleOp();
    int adventureEndStep();
    int adventureEndCnt();
    int adventureEndTime();
    int adventureRun();
    int pointSuccessLeave();
    int pointFailLeave();
    int savePng();
    int saveJpg();
    int setParams();
    int dutWmSizeShow();
    int dutWmSizeSet();
    int dutWmSizeReSet();
    int resumeAdb();
    int connect();
    int exit();

private:
    //DutShot* screenshot
    //DutFasterShot* screenshot;
    DutMiniShot* screenshot;
    Motion* motion;
    Scrcpy* dut;
    std::string uuid;
    int doCnt;

    //不收缩屏幕时用的变量
    const int bx = 1800; //27寸电脑窗口位置
    const int by = 50;
    const int bw = 604; //27寸电脑窗口大小
    const int bh = 1344;

    const int sx = 1390; //房间里面窗口位置
    const int sy = 50;
    const int sw = 442;  //房间里面窗口大小
    const int sh = 984;

    //收缩屏幕时用的变量
    const int shrinkBh = 1075;
};

