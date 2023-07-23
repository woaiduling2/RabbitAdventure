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

//��������Ŀ��ƽӿ���,�����������������,�������ܴӸ��ӿ������õ���Ҫ�Ķ���
class Ctl
{
public:
    Ctl();
    ~Ctl();
    Ctl(const Ctl&) = delete;  //�ѿ������캯��ɾ��
    int AdbCmd(const std::string adbInput, const std::string matchOut/*��Ҫ����Ŀ��Ŵ�whileѭ������,�򳬹���������*/, const std::string sign, bool debug = false);
    int AdbCmd(const std::string& cmd, std::string& pipe_data,int64_t timeout);
private:
    bool CreateOverlappablePipe(HANDLE* read, HANDLE* write, SECURITY_ATTRIBUTES* secattr_read,
        SECURITY_ATTRIBUTES* secattr_write, DWORD bufsize, bool overlapped_read,
        bool overlapped_write);
};

class Dut:public Ctl    //�����ֻ��������������,��������
{
public:
    bool bShrink;//dut�Ƿ�Ҫ������Ļ
    std::string uuid; //adb device���ֵĶ���
    explicit Dut()=delete;
    explicit Dut(const std::string gUuid,bool gB_Shrink);
    ~Dut();
    virtual int startUp() { printf("startUp unSupport!\n"); return -1; };   //����scrcpy
    int uuidConnect();
    int btnPress(int x, int y);
    int btnPress(int x, int y, int duration_ms/*��λ:����*/);
    int swipe(int sx, int sy, int ex, int ey, int duration_ms = 1000/*��λ:����*/, bool waitOff = false/*�Ƿ�ȴ�����*/);
    int motionMoveStart(int x1, int y1, int x2, int y2, int x3, int y3);
    int motionMoveEnd(int x3, int y3);
    virtual void disposing() { printf("disposing unSupport!\n"); return; }; //��Դ�ͷ�
};

class Scrcpy:public Dut   //�ֻ������и�scrcpyȥ����������������,���൱�����豸���������ʾ�߳�
{
public:
    bool bStartUp;
    PROCESS_INFORMATION* pi;
    HANDLE   hRead, hWrite;
    STARTUPINFO   si;
    bool bStayAwak;  //turn screen off and stay awake 
    bool bScreenOff; //turn-screen-off
    bool bFpsPrint;  //�Ƿ��ӡfps����
    bool bPositionX; //�Ƿ�ָ������x����
    bool bPositionY; //�Ƿ�ָ������y����
    bool bTopAlways; //�Ƿ��ö�����
    bool bScreenOffIfExit; //�ر�scrcpyʱ�Ƿ�����
    bool bBorderLess;//�Ƿ��ޱ߿���ʾ
    bool bWidth;     //�Ƿ����ô��ڿ��
    bool bHeight;    //�Ƿ����ô��ڸ߶�
    int positionX;
    int positionY;
    int scrcpyW;
    int scrcpyH;
    explicit Scrcpy()=delete;
    explicit Scrcpy(const std::string gUuid,bool gB_Shrink);
    explicit Scrcpy(const Scrcpy* one, bool gB_Shrink):Dut(one->uuid, gB_Shrink)   //�������캯��
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
    virtual void disposing()override; //��������������Դ�ͷ�

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

//��Ļ��ͼ����Դ���豸,������DUTҲ�����ǵ���,���ǵ����ϵ�ģ����
//����DUT�Ǿ���˵���õ�adb����,��Ҫ��adb�Ŀ���,�����ܷ���uuid
//���Ե���,˵���õ�����Ļ��ͼ�ķ�ʽ,��Ҫ֪����Ļ�����ű�
//����,���˲���֪�����Ǵ�������ͼƬ,��������ʲô,ȫ���������ͼ��õ�
class Screenshot   //����ͼƬ�����������,��ʶ�������
{
public:
    explicit Screenshot();
    //��ʵ���˲���֪������adb�õĽ�ͼ����pc�õĽ�ͼ,��ֻ�����õ���ͼ,����ʲô��?
    virtual cv::Mat screenShotGet() { printf("screenShotGet unSupport\n"); return cv::Mat(); };
    virtual cv::Mat screenShotGet(int x, int y, int width, int height) { printf("screenShotGet xywh unSupport\n"); return cv::Mat(); };
};

class PcShot :public Screenshot
{
public:
    double zoom;
    PcShot();
    ~PcShot();
    double zoomGet();         //��ȡ��Ļ����ֵ
    virtual cv::Mat screenShotGet()override;  //��ȡ������Ļ�Ľ�ͼ
    virtual cv::Mat screenShotGet(int x, int y, int width, int height)override;
private:
    int m_width;
    int m_height;
    HDC m_screenDC;
    HDC m_compatibleDC;
    HBITMAP m_hBitmap;
    LPVOID m_screenshotData = nullptr;
};

class DutShot:public Screenshot   //�Լ�д��ץͼ,����ץ����png
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

class DutFasterShot:public DutShot  //����д��ץͼ,����ץ����png,(������ѹ��ͼƬ����,Ч��������)
{
public:
    DutFasterShot()=delete;
    DutFasterShot(Dut* gDut);
    ~DutFasterShot();
    virtual cv::Mat screenShotGet()override;
private:
    const int m_width =  1080;   //�ֻ����
    const int m_height = 2400;
    bool decode_raw_with_gzip;   //�Ƿ���gzipѹ��ͼƬ
};

class DutMiniShot :public DutShot  //minicapץjpgͼ,��ָ������ȥץ,�ֻ�Ҫ��ͼƬ����һ��
{
public:
    DutMiniShot() = delete;
    DutMiniShot(Dut* gDut);
    ~DutMiniShot();
    virtual cv::Mat screenShotGet()override;
private:
};

//��һ��ʶ��,Ȼ����һЩ����
//�õ�����,ִ������?
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
        int ltx;  //����x
        int lty;  //����y
        int rbx;  //����x
        int rby;  //����y
        int cx;   //����������
        int cy;   //����������
    }point_s;      //sudo��ĸ���,��ͼ��ʵ��ռ�õĴ�С��������Ϣ

    typedef struct
    {
        point_s pt;
        bool bMatched; //�Ƿ�������,Ĭ����û����
        itemType_e type;
    }blockItem_s;      //sudo�еķ���ṹ��,����������������sudo

    void detectHSColor(const cv::Mat& image, double minHue, double maxHue, double minSat, double maxSat, cv::Mat& mask);
public:
    Motion(Dut*);
    ~Motion();
    int gameStartRun(const cv::Mat& src,int sign,bool debug=false);       //������Ϸҳ��
    int welcomeRun(const cv::Mat& src, int sign,bool debug=false);        //��ӭ������ҳ��
    int dailyLandingRun(const cv::Mat& src, int sign,bool debug=false);   //ÿ�յ�½��ҳ��
    int checkPointsRun(const cv::Mat& src,  int sign, int checkNum=1/*�ҵ���һ��*/, bool debug=false);  //�ؿ���ҳ��,���϶�ѡ��ؿ�
    int pointEnter(const cv::Mat& src, int sign,bool debug=false); //ָ������ĳ�ؿ�ʱ���ᵯ��ҳ������ʾ��Ҫʲô����
    int adventureRun(const cv::Mat& src, itemType_e targetType/*ÿ��ʶ��sudo��Ҫ����3����Ŀ������*/,bool bIncomeMax/*�Ƿ��������*/,bool bMostlySearch,int& targetMatchCnt/*ʵ��������������*/, int sign, bool debug = false);      //����ð�յ�����,����ҳ��,������1�ؿ����������ҳ���������Ѷȶ���
    int pointSuccessLeave(const cv::Mat& src, int sign, bool debug = false); //�ɹ�ʱ�ᵯ����ҳ��
    int pointFailLeave(const cv::Mat& src, int sign, bool debug=false);    //ʧ��ʱ�ᵯ����ҳ��
    int PicDirectoryGen(const char* dirName="Pic");
    int numRec(const cv::Mat& src, int sign); //ʶ��ؿ���
    std::string charRec(const cv::Mat& src, int sign); //ʶ���ַ�
    int adventureEndCnt(const cv::Mat& src, int sign, bool debug = false);
    int adventureEndStep(const cv::Mat& src, int sign, bool debug = false);
    int adventureEndTime(const cv::Mat& src, int sign, bool debug = false);
    int adventureSudo(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& sudoWidth, int& sudoHeight,int sign, bool debug = false);
    int adventureItemsByMoli(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& sudoWidth, int& sudoHeight, int& blockWidth, int& blockHight, cv::Mat& calDrawSrc, blockItem_s* itemByMolis, int sign, bool debug=false);
    int adventureItemsByCabbage(const cv::Mat& src, cv::Mat& sudoSrc, int& sudoLeftTopX, int& sudoLeftTopY, int& blockWidth, int& blockHight, cv::Mat& calDrawSrc, blockItem_s* itemByCabbages,int sign, bool debug=false);
    int LinkPathGen(blockItem_s* blockItems, itemType_e type,bool bMostlySearch/*�����ܵ��������·��*/, std::deque<DATA_S>& linkPath, int sign, bool debug = false);
    void idleOp(int sign, bool bFaster/*���ȴ�����,���ӿ��ٶ�*/ = false, bool debug = false);
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
        inflate_s.next_in = reinterpret_cast<z_const Bytef*>(data);    //������

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
    typedef int(Menu::* MenuFp)();  //����ָ��Menu�ĳ�Ա����ָ��

    std::map<int, MenuFp> menuFs =   //����
    {
        { 0,  NULL },       //��ΪmenuName�Ҳ����ͻ���һ��Ĭ��0,������������Ҫ�����и�NULL
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
    std::map<int, std::string> menuName =   //����������
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
    Menu(bool bSmallScreen/*�����Ǵ�������С��*/,  std::string gUuid, bool gB_Shrink, int gDoCnt);
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

    //��������Ļʱ�õı���
    const int bx = 1800; //27����Դ���λ��
    const int by = 50;
    const int bw = 604; //27����Դ��ڴ�С
    const int bh = 1344;

    const int sx = 1390; //�������洰��λ��
    const int sy = 50;
    const int sw = 442;  //�������洰�ڴ�С
    const int sh = 984;

    //������Ļʱ�õı���
    const int shrinkBh = 1075;
};

