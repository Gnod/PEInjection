// PEDemo1Dlg.cpp : implementation file
//

#include "stdafx.h"
#include "PEDemo1.h"
#include "PEDemo1Dlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPEDemo1Dlg dialog

CPEDemo1Dlg::CPEDemo1Dlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPEDemo1Dlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CPEDemo1Dlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPEDemo1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CPEDemo1Dlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CPEDemo1Dlg, CDialog)
	//{{AFX_MSG_MAP(CPEDemo1Dlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, OnButton1)
	ON_BN_CLICKED(IDC_BUTTON2, OnButton2)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPEDemo1Dlg message handlers

BOOL CPEDemo1Dlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here
	GetDlgItem(IDC_EDIT_PATH)->EnableWindow(FALSE);
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CPEDemo1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CPEDemo1Dlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CPEDemo1Dlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CPEDemo1Dlg::OnButton1() 
{
	// TODO: Add your control notification handler code here

	CString filePath;
	GetDlgItemText(IDC_EDIT_PATH, filePath);
	
	if(filePath == "")
	{
		MessageBox("请先选择一个文件!");
	}
	else
	{
		CopyFile(filePath, this->m_fileName,FALSE);
		ModifyPe(m_fileName," ");
	}
	
}



void CPEDemo1Dlg::ModifyPe(CString strFileName, CString strMsg)
{
	CString strErrMsg;
    HANDLE hFile, hMapping;
    void *basepointer;
    // 打开要修改的文件
    if ((hFile = CreateFile(strFileName, GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE, 0,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0)) == INVALID_HANDLE_VALUE)
    {
        AfxMessageBox("Could not open file.");
        return;
    }
    // 创建一个映射文件
    if (!(hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_COMMIT, 0, 0, 0)))
    {
        AfxMessageBox("Mapping failed.");
        CloseHandle(hFile);
        return;
    }
    // 把文件头映象存入baseointer
    if (!(basepointer = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)))
    {
        AfxMessageBox("View failed.");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hMapping);
    CloseHandle(hFile);
    CalcAddress(basepointer); // 得到相关地址
    UnmapViewOfFile(basepointer);

    if(dwSpace<555)
    {
        AfxMessageBox("No room to write the data!");
    }
    else
    {
        WriteFile(strFileName,strMsg); // 写文件
    }
    if ((hFile = CreateFile(strFileName, GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE, 0,
		OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0)) == INVALID_HANDLE_VALUE)
    {
        AfxMessageBox("Could not open file.");
        return;
    }
    CloseHandle(hFile);
}

void CPEDemo1Dlg::WriteFile(CString strFileName, CString strMsg)
{
	CString strAddress1,strAddress2;
    int ret;
    unsigned char waddress[4]={0};

    ret=_open(strFileName,_O_RDWR | _O_CREAT | _O_BINARY,_S_IREAD | _S_IWRITE);
    if(!ret)
    {
        AfxMessageBox("Error open");
        return;
    }
    // 把新的入口地址写入文件,程序的入口地址在偏移PE文件头开始第40位
    if(!WriteNewEntry(ret,(long)(dwPeAddress+40),dwNewEntryAddress))
		return;
    // 把对话框代码写入到应用程序中
   if(!WriteMessageBox(ret,(long)dwEntryWrite,"Test",strMsg)) 
		return;

    _close(ret);
}

BOOL CPEDemo1Dlg::WriteNewEntry(int ret, long offset, DWORD dwAddress)
{
	CString strErrMsg;
    long retf;
    unsigned char waddress[4]={0};
    retf=_lseek(ret,offset,SEEK_SET);

    if(retf==-1)
    {
        AfxMessageBox("Error seek.");
        return FALSE;
    }
    memcpy(waddress,StrOfDWord(dwAddress),4);
    retf=_write(ret,waddress,4);
    if(retf==-1)
    {
        strErrMsg.Format("Error write: %d",GetLastError());
        AfxMessageBox(strErrMsg);
        return FALSE;
    }
    return TRUE;
}

void CPEDemo1Dlg::CalcAddress(const void *base)
{
	IMAGE_DOS_HEADER * dos_head =(IMAGE_DOS_HEADER *)base;
    if (dos_head->e_magic != IMAGE_DOS_SIGNATURE)
    {
        AfxMessageBox("Unknown type of file.");
        return;
    } 

    peHeader * header;
    // 得到PE文件头
    header = (peHeader *)((char *)dos_head + dos_head->e_lfanew);
    if(IsBadReadPtr(header, sizeof(*header)))
    {
        AfxMessageBox("No PE header, probably DOS executable.");
        return;
    }

	DWORD size = header->opt_head.NumberOfRvaAndSizes;	//16
	DWORD resourceVirturalAddr = header->opt_head.DataDirectory[2].VirtualAddress; //0x00004000
	DWORD resourceSize = header->opt_head.DataDirectory[2].Size;					//0x000000e0
	pRESOURCE_DIRECTORY rscDirectory;
	rscDirectory = (pRESOURCE_DIRECTORY)((char *)dos_head + header->section_header[3].PointerToRawData);

	for(int j = 0; j < 8; j ++)
	{
		int ret = rscDirectory[j].NumberOfIdEntries;
		rscDirectory[j].DirectoryEntries[ret];
	}

    DWORD mods;
    char tmpstr[4]={0};
    if(strstr((const char *)header->section_header[0].Name,".text")!=NULL)
    {
        // 此段的真实长度
        dwVirtSize=header->section_header[0].Misc.VirtualSize;
        // 此段的物理偏移
        dwPhysAddress=header->section_header[0].PointerToRawData;
        // 此段的物理长度
        dwPhysSize=header->section_header[0].SizeOfRawData;
        // 得到PE文件头的开始偏移
        dwPeAddress=dos_head->e_lfanew;
        // 得到代码段的可用空间，用以判断可不可以写入我们的代码
        // 用此段的物理长度减去此段的真实长度就可以得到
        dwSpace=dwPhysSize-dwVirtSize;
        // 得到程序的装载地址，一般为0x400000
        dwProgRAV=header->opt_head.ImageBase;
        // 得到代码偏移，用代码段起始RVA减去此段的物理偏移
        // 应为程序的入口计算公式是一个相对的偏移地址，计算公式为：
        // 代码的写入地址+dwCodeOffset
        dwCodeOffset=header->opt_head.BaseOfCode-dwPhysAddress;
        // 代码写入的物理偏移
        dwEntryWrite=header->section_header[0].PointerToRawData + 
			header->section_header[0].Misc.VirtualSize;
        //对齐边界
        mods=dwEntryWrite%16;
        if(mods!=0)
        {
            dwEntryWrite+=(16-mods);
        }
        // 保存旧的程序入口地址
        dwOldEntryAddress=header->opt_head.AddressOfEntryPoint;
        // 计算新的程序入口地址       
        dwNewEntryAddress=dwEntryWrite+ dwCodeOffset;
       // return;
    }
	for(int i = 0; i < 4; i ++)
	{
		if(strstr((const char *)header->section_header[i].Name,".data")!=NULL)
		{
			// 此段的真实长度
			ldwVirtSize=header->section_header[i].Misc.VirtualSize;//0x00019902//0x000000e0
			// 此段的物理偏移
			ldwPhysAddress=header->section_header[i].PointerToRawData;//0x00001000//0x00000800
			// 此段的物理长度
			ldwPhysSize=header->section_header[i].SizeOfRawData;//0x0001a000//0x00000200
			// 得到PE文件头的开始偏移
			ldwPeAddress=dos_head->e_lfanew;				//0x000000e0//0x000000c8
			// 得到代码段的可用空间，用以判断可不可以写入我们的代码
			// 用此段的物理长度减去此段的真实长度就可以得到
			ldwSpace=dwPhysSize-dwVirtSize;	//0x000006fe//0x00000170
			// 得到程序的装载地址，一般为0x400000
			ldwProgRAV=header->opt_head.ImageBase;	//0x00400000//0x00400000
			// 得到代码偏移，用代码段起始RVA减去此段的物理偏移
			// 应为程序的入口计算公式是一个相对的偏移地址，计算公式为：
			// 代码的写入地址+dwCodeOffset
			ldwCodeOffset=header->opt_head.BaseOfData-ldwPhysAddress;//0x00000000//0x00000800
			// 代码写入的物理偏移
			ldwEntryWrite=header->section_header[i].PointerToRawData+header->
				section_header[i].Misc.VirtualSize;				//0x0001a902	//0x00000490  //0x00022798
			//对齐边界
			unsigned long lmods=ldwEntryWrite%16;
			if(lmods!=0)
			{
				ldwEntryWrite+=(16-lmods);
			}
			// 保存旧的程序入口地址
			ldwOldEntryAddress=header->opt_head.AddressOfEntryPoint;	//0x00001044
			// 计算新的程序入口地址       
			ldwNewEntryAddress=ldwEntryWrite;				//0x00001090//0x000185b7
			return;
		}
	}
}

BOOL CPEDemo1Dlg::WriteMessageBox(int ret, long offset, CString strCap, CString strTxt)
{
	CString strAddress1,strAddress2;
    unsigned char waddress[4]={0};
    DWORD dwAddress;
    // 获取MessageBox在内存中的地址
	
	HINSTANCE gLibMsg1 = LoadLibrary("comctl32.dll");
	this->dwInitCommonControlsAddress = (DWORD)GetProcAddress(gLibMsg1, "InitCommonControls");
	HINSTANCE gLibMsg2 = LoadLibrary("kernel32.dll");
	this->dwGetModuleHandleAddress = (DWORD)GetProcAddress(gLibMsg2, "GetModuleHandleA");
	this->dwRtlZeroMemoryAddress  = (DWORD)GetProcAddress(gLibMsg2, "RtlZeroMemory");
	HINSTANCE gLibMsg3 = LoadLibrary("user32.dll");
	this->dwDialogBoxParamAddress     = (DWORD)GetProcAddress(gLibMsg3, "DialogBoxParamA");
	this->dwLoadCursorAAddress        = (DWORD)GetProcAddress(gLibMsg3, "LoadCursorA");
	this->dwRegisterClassExAAddress   = (DWORD)GetProcAddress(gLibMsg3, "RegisterClassExA");
	this->dwCreateWindowExAAddress    = (DWORD)GetProcAddress(gLibMsg3, "CreateWindowExA");
	this->dwShowWindowAddress         = (DWORD)GetProcAddress(gLibMsg3, "ShowWindow");
	this->dwUpdateWindowAddress       = (DWORD)GetProcAddress(gLibMsg3, "UpdateWindow");
	this->dwGetMessageAAddress        = (DWORD)GetProcAddress(gLibMsg3, "GetMessageA");
	this->dwDispatchMessageAAddress   = (DWORD)GetProcAddress(gLibMsg3, "DispatchMessageA");
	this->dwSendMessageAAddress       = (DWORD)GetProcAddress(gLibMsg3, "SendMessageA");
	this->dwGetDlgItemTextAAddress    = (DWORD)GetProcAddress(gLibMsg3, "GetDlgItemTextA");
	this->dwDefWindowProcAAddress     = (DWORD)GetProcAddress(gLibMsg3, "DefWindowProcA");
	this->dwDestroyWindowAddress      = (DWORD)GetProcAddress(gLibMsg3, "DestroyWindow");
	this->dwPostQuitMessageAddress	  = (DWORD)GetProcAddress(gLibMsg3, "PostQuitMessage");
	this->dwTranslateMessageAddress   = (DWORD)GetProcAddress(gLibMsg3, "TranslateMessage");
	this->dwDestroyWindowAddress      = (DWORD)GetProcAddress(gLibMsg3, "DestroyWindow");

	HINSTANCE gLibMsg4 = LoadLibrary("kernel32.dll");
	this->dwExitProcessAddress = (DWORD)GetProcAddress(gLibMsg4, "ExitProcess");
	this->dwLstrcmpAAddress  = (DWORD)GetProcAddress(gLibMsg4, "lstrcmpA");
	
	HINSTANCE gLibMsg5 = LoadLibrary("user32.dll");
	DWORD dwEndDialogAddress = (DWORD)GetProcAddress(gLibMsg5, "EndDialog");


	HINSTANCE gLibMsg=LoadLibrary("user32.dll");
    dwMessageBoxAadaddress=(DWORD)GetProcAddress(gLibMsg,"MessageBoxA");
    // 计算校验位
    // 重新计算MessageBox函数的地址
    dwAddress=dwMessageBoxAadaddress-(dwProgRAV+dwNewEntryAddress + 456);
	CString strAddress0=StrOfDWord(dwAddress);

 	dwAddress=dwMessageBoxAadaddress-(dwProgRAV+dwNewEntryAddress + 477);
	strAddress1=StrOfDWord(dwAddress);
   
	dwAddress = this->dwDestroyWindowAddress - (dwProgRAV + dwNewEntryAddress +12 );
	CString strDestroyWindowAddress1 = this->StrOfDWord(dwAddress);

	dwAddress = this->dwExitProcessAddress - (dwProgRAV + dwNewEntryAddress +12 );
	CString strExitProcessAddress = this->StrOfDWord(dwAddress);
	dwAddress = this->dwExitProcessAddress - (dwProgRAV + dwNewEntryAddress + 456 );
	CString strExitProcessAddress1 = this->StrOfDWord(dwAddress);

	dwAddress = this->dwInitCommonControlsAddress - (dwProgRAV + dwNewEntryAddress + 23);
	CString strInitCommonControlsAddress = this->StrOfDWord(dwAddress);

	dwAddress = this->dwGetModuleHandleAddress - (dwProgRAV + dwNewEntryAddress + 30);
	CString strGetModuleHandleAddress = this->StrOfDWord(dwAddress);

	dwAddress = this->dwRtlZeroMemoryAddress - (dwProgRAV + dwNewEntryAddress + 41);
	CString strGRtlZeroMemoryAddress = this->StrOfDWord(dwAddress);

	dwAddress = this->dwLoadCursorAAddress - (dwProgRAV + dwNewEntryAddress + 53);
	CString strLoadCursorAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwRegisterClassExAAddress - (dwProgRAV + dwNewEntryAddress + 109);
	CString strRegisterClassExAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwCreateWindowExAAddress - (dwProgRAV + dwNewEntryAddress + 160);
	CString strCreateWindowExAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwShowWindowAddress - (dwProgRAV + dwNewEntryAddress + 178);
	CString strShowWindowAddress = this ->StrOfDWord(dwAddress);
	dwAddress = this->dwShowWindowAddress - (dwProgRAV + dwNewEntryAddress + 451);
	CString strShowWindowAddress1 = this ->StrOfDWord(dwAddress);


	dwAddress = this->dwUpdateWindowAddress  - (dwProgRAV + dwNewEntryAddress + 189);
	CString strUpdateWindowAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwCreateWindowExAAddress - (dwProgRAV + dwNewEntryAddress + 241);
	CString strCreateWindowExAAddress1 = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwCreateWindowExAAddress - (dwProgRAV + dwNewEntryAddress + 290);
	CString strCreateWindowExAAddress2 = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwGetMessageAAddress  - (dwProgRAV + dwNewEntryAddress + 305);
	CString strGetMessageAAddress = this ->StrOfDWord(dwAddress);
	
	dwAddress = this->dwTranslateMessageAddress   - (dwProgRAV + dwNewEntryAddress + 318);
	CString strTranslateMessageAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwDispatchMessageAAddress    - (dwProgRAV + dwNewEntryAddress + 327);
	CString strDispatchMessageAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwSendMessageAAddress     - (dwProgRAV + dwNewEntryAddress + 377);
	CString strSendMessageAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwGetDlgItemTextAAddress      - (dwProgRAV + dwNewEntryAddress + 422);
	CString strGetDlgItemTextAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwLstrcmpAAddress      - (dwProgRAV + dwNewEntryAddress + 437);
	CString strLstrcmpAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwDefWindowProcAAddress       - (dwProgRAV + dwNewEntryAddress + 508);
	CString strDefWindowProcAAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwDestroyWindowAddress        - (dwProgRAV + dwNewEntryAddress + 535);
	CString strDestroyWindowAddress = this ->StrOfDWord(dwAddress);

	dwAddress = this->dwPostQuitMessageAddress    - (dwProgRAV + dwNewEntryAddress + 542);
	CString strPostQuitMessageAddress = this ->StrOfDWord(dwAddress);
	//////////////////////////////
	dwAddress = this->dwInitCommonControlsAddress -	(dwProgRAV+dwNewEntryAddress+ 5);
	CString strAddr1 = StrOfDWord(dwAddress);

	dwAddress = this->dwGetModuleHandleAddress - (dwProgRAV+dwNewEntryAddress+ 12);
	CString strAddr2 = StrOfDWord(dwAddress);

	dwAddress = this->dwDialogBoxParamAddress - (dwProgRAV+dwNewEntryAddress+ 39);
	CString strAddr3 = StrOfDWord(dwAddress);

	dwAddress = dwProgRAV+dwNewEntryAddress  - 68;
	CString strAddr4 = StrOfDWord(dwAddress);
    // 计算返回地址
    dwAddress=0-(dwNewEntryAddress-dwOldEntryAddress+456);
    strAddress2=StrOfDWord(dwAddress);

	dwAddress = this->dwExitProcessAddress-	(dwProgRAV+dwNewEntryAddress+ 46);
	CString strAddr5 = StrOfDWord(dwAddress);

	dwAddress = dwProgRAV+dwNewEntryAddress  - 68 + 0x2000;
	CString strAddr6 = StrOfDWord(dwAddress);

	dwAddress = dwEndDialogAddress  -	(dwProgRAV+dwNewEntryAddress- 68 + 24);
	CString strAddr7 = StrOfDWord(dwAddress);

	dwAddress = dwProgRAV + dwNewEntryAddress + 331;
	CString addr1 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress ; 
	CString addr2 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x11; 
	CString addr3 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress  + 0; 
	CString addr4 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x2E; 
	CString addr5 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x2B; 
	CString addr6 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x24; 
	CString addr7 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x50; 
	CString addr8 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x20; 
	CString addr9 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x11; 
	CString addr10 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x33; 
	CString addr15 = StrOfDWord(dwAddress);

	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x38; 
	CString addr11 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x3C; 
	CString addr12 = StrOfDWord(dwAddress);
	dwAddress = ldwProgRAV + this->ldwNewEntryAddress + 0x40; 
	CString addr13 = StrOfDWord(dwAddress);

	




	unsigned char body2[66]={
		0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 
		0x54, 0x65, 0x6D, 0x70, 0x6C, 0x61, 0x74, 0x65, 
		0x00, 0x45, 0x6E, 0x74, 0x65, 0x72, 0x20, 0x50, 
		0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x00, 
		0x31, 0x32, 0x33, 0x00, 0x62, 0x75, 0x74, 0x74, 0x6F, 
		0x6E, 0x00, 0x4F, 0x4B, 0x00, 0x45, 0x64, 0x69,
		0x74, 0x00, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x00, 
		0x50, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 
	};
	TRACE("SDF");
	unsigned char body[543] = {
	0xE8, 0x07, 0x00, 0x00, 0x00,
	0x6A, 0x00, 
	0xE8,0x00,0x00,0x00,0x00,
	0x55, 
	0x8B, 0xEC, 
	0x83, 0xC4, 0xB4,
	0xE8, 0x79, 0x02, 0x00, 0x00, 
	0x6A, 0x00, 
	0xE8, 0x60, 0x02, 0x00, 0x00, 
	0x6A, 0x30, 
	0x8D, 0x45, 0xD0,
	0x50, 
	0xE8, 0x5B, 0x02, 0x00, 0x00,
	0x68, 0x00, 0x7F, 0x00, 0x00,
	0x6A, 0x00, 
	0xE8, 0x13, 0x02, 0x00, 0x00,
	0x89, 0x45, 0xEC,
	0xFF, 0x35, 0x38, 0x30, 0x40, 0x00, 
	0x8F, 0x45, 0xE4, 
	0xC7, 0x45, 0xD0, 0x30, 0x00, 0x00, 0x00,
	0xC7, 0x45, 0xD4, 0x03, 0x00, 0x00, 0x00,
	0xC7, 0x45, 0xD8, 0x4B, 0x11, 0x40, 0x00,
	0xC7, 0x45, 0xF0, 0x05, 0x00, 0x00, 0x00,
	0xC7, 0x45, 0xF8, 0x00, 0x30, 0x40, 0x00, 
	0x8D, 0x45, 0xD0,
	0x50, 
	0xE8, 0xED, 0x01, 0x00, 0x00,
	0x6A, 0x00, 
	0xFF, 0x35, 0x38, 0x30, 0x40, 0x00,
	0x6A, 0x00, 
	0x6A, 0x00, 
	0x68, 0xC8, 0x00, 0x00, 0x00,
	0x68, 0x2C, 0x01, 0x00, 0x00, 
	0x6A, 0x64, 
	0x6A, 0x64, 
	0x68, 0x00, 0x00, 0xCF, 0x00, 
	0x68, 0x11, 0x30, 0x40, 0x00, 
	0x68, 0x00, 0x30, 0x40, 0x00, 
	0x68, 0x00, 0x02, 0x00, 0x00,
	0xE8, 0x84, 0x01, 0x00, 0x00,
	0xA3, 0x3C, 0x30, 0x40, 0x00, 
	0x6A, 0x01,
	0xFF, 0x35, 0x3C, 0x30, 0x40, 0x00,
	0xE8, 0xB4, 0x01, 0x00, 0x00,
	0xFF, 0x35, 0x3C, 0x30, 0x40, 0x00,
	0xE8, 0xB5, 0x01, 0x00, 0x00, 
	0x6A, 0x00, 
	0xFF, 0x35, 0x38, 0x30, 0x40, 0x00,
	0x68, 0xA2, 0x0F, 0x00, 0x00,
	0xFF, 0x35, 0x3C, 0x30, 0x40, 0x00, 
	0x6A, 0x18, 
	0x68, 0x87, 0x00, 0x00, 0x00,
	0x6A, 0x32, 
	0x6A, 0x50, 
	0x68, 0x20, 0x00, 0x01, 0x50,
	0x6A, 0x00, 
	0x68, 0x2E, 0x30, 0x40, 0x00, 
	0x68, 0x00, 0x02, 0x00, 0x00,
	0xE8, 0x33, 0x01, 0x00, 0x00,
	0x6A, 0x00, 
	0xFF, 0x35, 0x38, 0x30, 0x40, 0x00,
	0x68, 0xA3, 0x0F, 0x00, 0x00, 
	0xFF, 0x35, 0x3C, 0x30, 0x40, 0x00,
	0x6A, 0x16,
	0x6A, 0x41,
	0x6A, 0x64,
	0x6A, 0x6E,
	0x68, 0x00, 0x00, 0x00, 0x50,
	0x68, 0x2B, 0x30, 0x40, 0x00,
	0x68, 0x24, 0x30, 0x40, 0x00,
	0x6A, 0x00,
	0xE8, 0x02, 0x01, 0x00, 0x00,
	0x6A, 0x00, 
	0x6A, 0x00,
	0x6A, 0x00, 
	0x8D, 0x45, 0xB4, 
	0x50, 
	0xE8, 0x11, 0x01, 0x00, 0x00,
	0x0B, 0xC0, 
	0x74, 0x14,
	0x8D, 0x45, 0xB4,
	0x50, 
	0xE8, 0x2E, 0x01, 0x00, 0x00,
	0x8D, 0x45, 0xB4, 
	0x50, 
	0xE8, 0xEF, 0x00, 0x00, 0x00,
	0xEB, 0xD9,
	0xC9,
	0xC3,
	0x55,
	0x8B, 0xEC,
	0x53, 
	0x57, 
	0x56,
	0x8B, 0x45, 0x0C, 
	0x83, 0xF8, 0x01, 
	0x75, 0x25,
	0x8B, 0x45, 0x08,
	0xA3, 0x3C, 0x30, 0x40, 0x00,
	0xFF, 0x35, 0x40, 0x30, 0x40, 0x00,
	0x6A, 0x00, 
	0x68, 0x80, 0x00, 0x00, 0x00,
	0xFF, 0x35, 0x3C, 0x30, 0x40, 0x00,
	0xE8, 0xE7, 0x00, 0x00, 0x00,
	0xE9, 0x85, 0x00, 0x00, 0x00,
	0x3D, 0x11, 0x01, 0x00, 0x00, 
	0x75, 0x5A, 
	0x8B, 0x45, 0x10, 
	0x3D, 0xA3, 0x0F, 0x00, 0x00,
	0x75, 0x74, 
	0x68, 0x00, 0x01, 0x00, 0x00,
	0x68, 0x50, 0x30, 0x40, 0x00, 
	0x68, 0xA2, 0x0F, 0x00, 0x00, 
	0xFF, 0x75, 0x08, 
	0xE8, 0x96, 0x00, 0x00, 0x00, 
	0x68, 0x50, 0x30, 0x40, 0x00, 
	0x68, 0x20, 0x30, 0x40, 0x00, 
	0xE8, 0xD5, 0x00, 0x00, 0x00, 
	0x0B, 0xC0, 
	0x75, 0x11,			//````

	0x6A, 0x00,
	0xFF, 0x75, 0x08, 
	0xE8, 0xAD, 0x00, 0x00, 0x00,  

	0xE9, 0x20, 0x30, 0x40, 0x00,

	0xEB, 0x13, 
	0x6A, 0x00, 
	0x68, 0x50, 0x30, 0x40, 0x00, 
	0x68, 0x33, 0x30, 0x40, 0x00, 
	0x6A, 0x00, 
	0xE8, 0x6D, 0x00, 0x00, 0x00, 
	0xEB, 0x24, 
	0x83, 0xF8, 0x10, 
	0x75, 0x07, 
	0xE8, 0x23, 0x00, 0x00, 0x00, 
	0xEB, 0x18, 
	0xFF, 0x75, 0x14, 
	0xFF, 0x75, 0x10, 
	0xFF, 0x75, 0x0C,
	0xFF, 0x75, 0x08, 
	0xE8, 0x2A, 0x00, 0x00, 0x00, 
	0x5E,
	0x5F, 
	0x5B, 
	0xC9, 
	0xC2, 0x10, 0x00, 
	0x33, 0xC0, 
	0x5E, 
	0x5F, 
	0x5B, 
	0xC9, 
	0xC2, 0x10, 0x00, 
	0xFF, 0x35, 0x3C, 0x30, 0x40, 0x00, 
	0xE8, 0x15, 0x00, 0x00, 0x00, 
	0x6A, 0x00, 
	0xE8, 0x32, 0x00, 0x00, 0x00, 
	0xC3
};

	

	for(int i = 0; i < 4; i ++)
	{
		body[8 + i] = strExitProcessAddress.GetAt(i);
		body[19 + i] = strInitCommonControlsAddress.GetAt(i);
		body[26 + i] = strGetModuleHandleAddress.GetAt(i);
		body[37 + i] = strGRtlZeroMemoryAddress.GetAt(i);
		body[49 + i] = strLoadCursorAAddress.GetAt(i);
		body[105 + i] = strRegisterClassExAAddress.GetAt(i);
		body[156 + i] = strCreateWindowExAAddress.GetAt(i);
		body[174 + i] = strShowWindowAddress.GetAt(i);
		body[185 + i] = strUpdateWindowAddress.GetAt(i);
		body[237 + i] = strCreateWindowExAAddress1.GetAt(i);
		body[286 + i] = strCreateWindowExAAddress2.GetAt(i);
		body[301+ i] = strGetMessageAAddress.GetAt(i);
		body[314+ i] = strTranslateMessageAddress.GetAt(i);
		body[323+ i] = strDispatchMessageAAddress.GetAt(i);
		body[373+ i] = strSendMessageAAddress.GetAt(i);
		body[418+ i] = strGetDlgItemTextAAddress.GetAt(i);
		body[433+ i] = strLstrcmpAAddress.GetAt(i);
//		body[456 + i] = strExitProcessAddress1.GetAt(i);
		body[473 + i] = strAddress1.GetAt(i);
		body[504+ i] = strDefWindowProcAAddress.GetAt(i);
		body[531+ i] = strDestroyWindowAddress.GetAt(i);
		body[538+ i] = strPostQuitMessageAddress.GetAt(i);

		body[82 + i ] = addr1.GetAt(i);
		body[96 + i ] = addr2.GetAt(i);
		body[141 + i] = addr3.GetAt(i);
		body[146 + i] = addr4.GetAt(i);
		body[227 + i ] = addr5.GetAt(i);
		body[274 + i ] = addr6.GetAt(i);
		body[279 + i] = addr7.GetAt(i);
		body[405 + i] = addr8.GetAt(i);
		body[423 + i] = addr8.GetAt(i);
		body[428 + i] = addr9.GetAt(i);
		body[447 + i] = strShowWindowAddress1.GetAt(i);
		body[452 + i] = strAddress2.GetAt(i);
		body[461 + i] = addr10.GetAt(i);
		body[466 + i] = addr15.GetAt(i);

		body[58 + i] = addr11.GetAt(i);
		body[113 + i] = addr11.GetAt(i);
		body[161 + i] = addr12.GetAt(i);
		body[169 + i] = addr12.GetAt(i);
		body[180 + i] = addr12.GetAt(i);
		body[193 + i] = addr11.GetAt(i);
		body[204 + i] = addr12.GetAt(i);
		body[245 + i] = addr11.GetAt(i);
		body[256 + i] = addr12.GetAt(i);
		body[349 + i] = addr12.GetAt(i);
		body[355 + i] = addr13.GetAt(i);
		body[368 + i] = addr12.GetAt(i);
		body[526 + i] = addr12.GetAt(i);
	}

    char* cMessageBox=new char[543];
	char* cMessageBox1= new char[66];

    char* cMsg;
	char* cMsg1;
    // 生成对话框命令字符串
    memcpy((cMsg  = cMessageBox),(char*)body,543);
	memcpy((cMsg1  = cMessageBox1),(char*)body2,66);
	
    // 向应用程序写入对话框代码
    CString strErrMsg;
    long retf;
    retf=_lseek(ret,(long)dwEntryWrite,SEEK_SET);
    if(retf==-1)
    {
        delete[] cMessageBox;
        AfxMessageBox("Error seek.");
        return FALSE;
    }
    retf=_write(ret,cMessageBox,543);
    if(retf==-1)
    {
        delete[] cMessageBox;
        strErrMsg.Format("Error write: %d",GetLastError());
        AfxMessageBox(strErrMsg);
        return FALSE;
    }
    delete[] cMessageBox;	


	retf=_lseek(ret,(long)ldwEntryWrite,SEEK_SET);
    if(retf==-1)
    {
        delete[] cMessageBox1;
        AfxMessageBox("Error seek.");
        return FALSE;
    }
    retf=_write(ret,cMessageBox1,66);
    if(retf==-1)
    {
        delete[] cMessageBox1;
        strErrMsg.Format("Error write: %d",GetLastError());
        AfxMessageBox(strErrMsg);
        return FALSE;
    }
    delete[] cMessageBox1;
    return TRUE;
}

CString CPEDemo1Dlg::StrOfDWord(DWORD dwAddress)
{
	unsigned char waddress[4]={0};
    waddress[3]=(char)(dwAddress>>24)&0xFF;
    waddress[2]=(char)(dwAddress>>16)&0xFF;
    waddress[1]=(char)(dwAddress>>8)&0xFF;
    waddress[0]=(char)(dwAddress)&0xFF;

    return waddress;
}

void CPEDemo1Dlg::OnButton2() 
{
	CString filter;
	filter = "(*.exe)|*.exe||*.*";
	CFileDialog dlg(TRUE,NULL,NULL,OFN_HIDEREADONLY,filter);

	if(dlg.DoModal()==IDOK)
	{
		CString str = dlg.GetPathName();
		SetDlgItemText(IDC_EDIT_PATH, str);

		CFile file(str, CFile::modeRead);
		CString fileName = file.GetFileName();
		int index = str.ReverseFind('\\') + 1;
		CString path;
		path = str.Left(index);

		this->m_fileName.Format("%sEX%s", path, fileName);
		file.Close();
	}	

	
}
