// PEDemo1Dlg.h : header file
//

#if !defined(AFX_PEDEMO1DLG_H__19D109DF_A280_45F3_9669_5D3EB83CF74D__INCLUDED_)
#define AFX_PEDEMO1DLG_H__19D109DF_A280_45F3_9669_5D3EB83CF74D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


#include <windows.h> 
#include <stdio.h> 
#include <io.h> 
#include <fcntl.h> 
#include <time.h> 
#include <SYS\STAT.H>
#include <pshpack1.h>
#include <poppack.h>
/////////////////////////////////////////////////////////////////////////////
// CPEDemo1Dlg dialog
typedef struct PE_HEADER_MAP
{

    DWORD signature;

    IMAGE_FILE_HEADER _head;

    IMAGE_OPTIONAL_HEADER opt_head;

    IMAGE_SECTION_HEADER section_header[6];

}peHeader;

typedef struct RESOURCE_DIRECTORY {

    DWORD Characteristics;

    DWORD TimeDateStamp;

    WORD MajorVersion;

    WORD MinorVersion;

    WORD NumberOfNamedEntries;

    WORD NumberOfIdEntries;

    IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];

} *pRESOURCE_DIRECTORY;



class CPEDemo1Dlg : public CDialog
{
// Construction
public:
	CString m_fileName;
	CString StrOfDWord(DWORD dwAddress);
	BOOL WriteMessageBox(int ret,long offset,CString strCap,CString strTxt);
	BOOL WriteNewEntry(int ret,long offset,DWORD dwAddress);
	void WriteFile(CString strFileName,CString strMsg);
	void ModifyPe(CString strFileName,CString strMsg);
	void CalcAddress(const void *base);
	CPEDemo1Dlg(CWnd* pParent = NULL);	// standard constructor

	DWORD dwSpace;
    DWORD dwEntryAddress;
    DWORD dwEntryWrite;
    DWORD dwProgRAV;
    DWORD dwOldEntryAddress;
    DWORD dwNewEntryAddress;
    DWORD dwCodeOffset;
    DWORD dwPeAddress;
    DWORD dwFlagAddress;
    DWORD dwVirtSize;
    DWORD dwPhysAddress;
    DWORD dwPhysSize;
    DWORD dwMessageBoxAadaddress;
	DWORD dwInitCommonControlsAddress;
	DWORD dwGetModuleHandleAddress;
	DWORD dwDialogBoxParamAddress;
	DWORD dwExitProcessAddress;

	DWORD ldwOldEntryAddress;
	DWORD ldwNewEntryAddress;
	DWORD ldwProgRAV;
	DWORD ldwCodeOffset;
	DWORD ldwEntryWrite;
	DWORD ldwSpace;
	DWORD ldwPeAddress;
	DWORD ldwPhysSize;
	DWORD ldwPhysAddress;
	DWORD ldwVirtSize;

	DWORD dwRtlZeroMemoryAddress;
	DWORD dwLoadCursorAAddress;
	DWORD dwRegisterClassExAAddress;
	DWORD dwCreateWindowExAAddress;
	DWORD dwShowWindowAddress;
	DWORD dwUpdateWindowAddress;
	DWORD dwGetMessageAAddress;
	DWORD dwDispatchMessageAAddress;
	DWORD dwSendMessageAAddress;
	DWORD dwGetDlgItemTextAAddress;
	DWORD dwLstrcmpAAddress;
	DWORD dwDefWindowProcAAddress;
	DWORD dwDestroyWindowAddress;
	DWORD dwPostQuitMessageAddress;
	DWORD dwTranslateMessageAddress;

// Dialog Data
	//{{AFX_DATA(CPEDemo1Dlg)
	enum { IDD = IDD_PEDEMO1_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CPEDemo1Dlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CPEDemo1Dlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnButton1();
	afx_msg void OnButton2();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_PEDEMO1DLG_H__19D109DF_A280_45F3_9669_5D3EB83CF74D__INCLUDED_)
