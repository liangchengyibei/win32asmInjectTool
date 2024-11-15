
.586
.model flat,stdcall
option casemap:none
include Windows.inc
include user32.inc
includelib user32.lib
include kernel32.inc
includelib kernel32.lib
include comdlg32.inc
includelib comdlg32.lib
include psapi.inc
includelib psapi.lib
include msvcrt.inc
includelib msvcrt.lib
;�������xedparse
includelib XEDParse_x86.lib


IDD_DLG_MAIN equ 1000
IDC_BTN_PROCESS equ 1001
IDC_EDT_PROCESS equ 1003
IDC_BTN_INJECT equ 1002
IDC_CODE equ 1004
IDC_LISTVIEW equ 1005
IDD_DLG_LISTVIEW equ 1100
IDC_LST_PROCESS equ 1101
IDC_BTN_OK equ 1102

;����xedParseҪ�õĽṹ������


;ͨ��vs�������ṹ���˹�����
XEDPARSE struct

	_x64 dw 0 ;use 64-bit instructions
	x1 dw 0
	x2 dd 0
	x3 dd 0
 	_cip dd 0 ;instruction pointer (for relative addressing)
	
	_dest_size dd 0 ;destination size (returned by XEDParse)

	_cbUnknown dd 0 ;unknown operand callback

	_dest db 16 dup(0) ;destination buffer

	_instr db 256 dup(0) ;instruction text

	_error db 256 dup(0) ;error text (in case of an error)
XEDPARSE ends

;�Զ�����Ϣ
MSG_UPDATA_EDITPRO equ WM_USER + 100

.data
	hDlgMain dd 0
	szTips db "ѡ����̳ɹ�",0
	pProcess dd 1024 dup(0)
	szListView db "SysListView32",0
	szDllEdit db "RichEd20.dll",0
	szClassEdit db "RichEdit20A",0
	;���ı����ھ��
	hWinEdit dd 0
	hInstance dd 0
	szBuf db 1024 dup(0)
	szFmtX db "%08x",0
	szFmtS db "%s",0
	hDlgList dd 0
	proNameBuf db 1024 dup(0)
	szErrorWrite db "д��Ŀ�����ʧ��",0
pCodeBuf db 1024 dup(0)
.code

;����Ҫע��Ķ����ƻ�����


;����xedParse�еĵ��뺯��
XEDParseAssemble proto C :ptr XEDPARSE
CBXEDPARSE_UNKNOWN proto C :LPBYTE,:ptr dword


_ZeroMem proc pBuf:LPBYTE,cb:dword
	pushad
	mov esi,pBuf
	mov ecx,cb
	.if ecx<=0
		ret
	.endif
	.while TRUE 
		mov byte ptr [esi],0
		inc esi
		dec ecx
		.break .if ecx<=0
	.endw
	popad
	ret
_ZeroMem endp


GetDestProcessHandle proc DestProName:LPSTR
	
	local @DestHandle:dword
	local @cbNeeded:dword
	local @cProcesses:dword
	local @hMod:dword
	local @hProcess:dword
	local @arrProcess:dword
	local @szProcessName:dword 
	;g_arrProcess
	sub esp,1024*4
	mov @arrProcess,esp
	;ʹ��EnumProcesses��ȡ����id�б�
	invoke EnumProcesses,@arrProcess,1024*4,addr @cbNeeded
	
	mov eax,@cbNeeded
	shr eax,4
	mov @cProcesses,eax
	
	mov ecx,@cProcesses
	mov esi,@arrProcess
	.while TRUE
		.if ecx<=0
			.break
		.endif
		;������
		sub esp,256
		mov @szProcessName,esp
		invoke OpenProcess,PROCESS_ALL_ACCESS,NULL,[esi]
		add esi,4
		.if eax
			mov @hProcess,eax
			invoke EnumProcessModules,@hProcess,addr @hMod,4,addr @cbNeeded
			invoke GetModuleBaseName,@hProcess,@hMod,@szProcessName,256
		.endif
		invoke crt_strcmp,DestProName,@szProcessName
		.if eax == 0
			;mov eax,[esi-4]
			mov eax,@hProcess
			add esp,256
			jmp @F
		.endif
		add esp,256
		dec ecx
	.endw
	xor eax,eax
@@:	
	add esp,1024*4
	ret
GetDestProcessHandle endp

GetContextProcessList proc hWndList:HWND
	local @cbNeeded:dword
	local @cProcesses:dword
	local @hProcess:dword
	local @pid:dword
	;�������500������
	local @proName[1024]:byte
	pushad
	
	invoke EnumProcesses,offset pProcess,1024*4,addr @cbNeeded
	mov eax,@cbNeeded
	shr eax,2
	mov @cProcesses,eax
	;@cProcesses�����ڴ���ʵ�ʽ�����
	xor edi,edi
	lea esi,pProcess
	
	.while TRUE
		
		mov eax,dword ptr [esi + edi *4]
		mov @pid,eax
		;ebx = pid
		invoke OpenProcess,PROCESS_ALL_ACCESS,FALSE,@pid
		.if eax== NULL
			inc edi
			.continue
		.else 
			
			mov @hProcess,eax
			invoke GetModuleBaseName,@hProcess,NULL,addr @proName,1024
			.if eax != NULL
				invoke SendMessage,hWndList,LB_ADDSTRING,0,addr @proName
			.endif
			invoke CloseHandle,@hProcess
		.endif
		inc edi
		.break .if edi>=@cProcesses
	.endw

	popad
	ret
GetContextProcessList endp

;list dlgProc
_dlgFunListView proc hwnd:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
	
	local @buf[1024]:byte
	local @index
	pushad 
	mov eax,uMsg

	.if eax == WM_CLOSE
		invoke EndDialog,hwnd,0
		jmp _do
	.elseif eax == WM_INITDIALOG
		
		invoke GetDlgItem,hwnd,IDC_LST_PROCESS
		mov hDlgList,eax
		
		invoke GetContextProcessList,hDlgList
		jmp _do
	.elseif eax == WM_COMMAND
		mov eax,wParam
		.if eax == IDC_BTN_OK
			invoke SendMessage,hDlgList,LB_GETCURSEL,0,0
			mov @index,eax
			invoke SendMessage,hDlgList,LB_GETTEXT,@index,offset proNameBuf
			;invoke MessageBox,0,addr @buf,0,0
			invoke MessageBox,NULL,offset szTips,0,0
			invoke SendMessage,hDlgMain,MSG_UPDATA_EDITPRO,0,0
			invoke EndDialog,hwnd,0
		.endif
		jmp _do
	.else		
		jmp _do_false
	.endif
_do:
	popad
	mov eax,TRUE
	ret
_do_false:	
	popad
	xor eax,eax
	ret
_dlgFunListView endp

;����listview�Ի���
_CreateListView proc hwnd:HWND
	
	pushad
	
	invoke DialogBoxParam,NULL,IDD_DLG_LISTVIEW,hwnd,offset _dlgFunListView,NULL
	popad
	ret
_CreateListView endp


;xde�ص�

_cbUnknow proc text:LPBYTE,value:ptr dword
	pushad
	popad
	ret
_cbUnknow endp

;����XEDParse ���pBuf�еĴ���
_AsmCode proc pBuf:LPBYTE,cb:dword,startCip:dword
	local @dwRet;�����ܹ�����˶����ֽڵ�ָ��
	local @xed:XEDPARSE

	local @cip
	pushad
	;���ǳ�ʼ��ip�ˡ�������
	push startCip
	pop @cip
	mov @dwRet,0

	;invoke _ZeroMem,addr @xed,sizeof XEDPARSE
	;���XEDPARSE
	;mov @xed._x64,FALSE
	;mov @xed._cip,0
	;invoke crt_strcpy,addr @xed._instr,pBuf
	;����XEDParseAssemble
	;invoke XEDParseAssemble,addr @xed
	xor ecx,ecx
	mov esi,pBuf	
	mov edi,offset pCodeBuf
	.while TRUE
		push ecx;����ĳЩϵͳapi��ı�ecx��ֵ		
		.if byte ptr [esi + ecx] == 0dh
			;ecx = instr size
			push esi
			push edi
			invoke _ZeroMem,addr @xed,sizeof XEDPARSE
			mov @xed._x64,FALSE
			push @cip
			pop @xed._cip
			
			invoke crt_memcpy,addr @xed._instr,esi,ecx
			invoke XEDParseAssemble,addr @xed
			mov eax,@xed._cip
			add @cip,eax
			mov eax,@xed._dest_size
			add @dwRet,eax
			pop edi
			invoke crt_memcpy,edi,addr @xed._dest,@xed._dest_size
			add edi,@xed._dest_size
			pop esi
			pop ecx
			add esi,ecx
			add esi,2
			xor ecx,ecx
		.else 
			pop ecx
			inc ecx
		.endif
		
		.break .if ecx>=cb
	.endw
	popad
	mov eax,@dwRet
	ret
_AsmCode endp


;ע����̺���
_InjectProcCode proc hProc:dword,pBuf:LPBYTE,cb:dword
	local @lpBaseAddress ;Ŀ����̷�����ڴ����ַ
	local @code_size ;pCodeBuf�ֽ����С
	pushad	
	
	invoke VirtualAllocEx,hProc,NULL,1024,\
	MEM_COMMIT or MEM_RESERVE,PAGE_EXECUTE_READWRITE
	mov @lpBaseAddress,eax

	;pbuf is the text 
	;cb is buf size
	;@lpBaseAddress is start cip
	 
	;ע��֮ǰ�����øɼ���,���@injectcodeBuf�е����ݣ�����ת��Ϊ2����
	invoke _AsmCode,pBuf,cb,@lpBaseAddress
	mov @code_size,eax
	;invoke wsprintf,offset szBuf,offset szFmtS,addr pCodeBuf
	;invoke MessageBox,0,offset szBuf,0,0
	;ת����Ķ����Ʊ�����pCodeBuf��
	invoke WriteProcessMemory,hProc,@lpBaseAddress,addr pCodeBuf,@code_size,NULL
	.if eax==0
		invoke MessageBox,NULL,offset szErrorWrite,0,0
		mov eax,FALSE
		ret
	.endif
	;Զ�߳�ע��
	
	invoke wsprintf,offset szBuf,offset szFmtX,@lpBaseAddress
	invoke MessageBox,0,offset szBuf,0,0
	invoke CreateRemoteThread,hProc,NULL,0,@lpBaseAddress,0,0,0
	popad
	mov eax,TRUE
	ret
_InjectProcCode endp

;EM_STREAMOUT �ص�����
_EditstreamcallbackProc proc dwCookie:dword,pbBuff:LPBYTE,cb:LONG,pcb:ptr LONG
	local @dwRet:dword
	pushad
	mov @dwRet,0
	invoke  crt_memcpy,dwCookie,pbBuff,cb
	popad
	mov eax,@dwRet
	ret
_EditstreamcallbackProc endp

dlgProc_main proc hwnd:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
	local @hEditProcess
	local @szBuf[1024]:byte
	local @hDestProc
	local @es:EDITSTREAM
	local @hRichEdit
	local @injectcodeBuf[1024]:byte
	local @gtl:GETTEXTLENGTHEX
	local @editTextLength

	pushad 
	
	mov eax,uMsg
	
	.if eax == WM_INITDIALOG
		push hwnd
		pop hDlgMain
		jmp _do
	.elseif eax == WM_CLOSE
		invoke EndDialog,hwnd,0
		jmp _do

			
	.elseif eax == MSG_UPDATA_EDITPRO
		;invoke MessageBox,0,offset proNameBuf,0,0
		;��ȡ�ؼ����
		invoke GetDlgItem,hwnd,IDC_EDT_PROCESS
		mov @hEditProcess,eax
		invoke SetWindowText,@hEditProcess,offset proNameBuf
		jmp _do
	.elseif eax == WM_COMMAND
		mov eax,wParam
		;ѡ�����
		.if eax == IDC_BTN_PROCESS
			invoke _CreateListView,hwnd
		;ע��	
		.elseif eax == IDC_BTN_INJECT		
			;no1 ��ȡedit�ؼ������ݣ���ȡ����Ȩ��
			invoke GetDlgItem,hwnd,IDC_EDT_PROCESS
			mov @hEditProcess,eax
			invoke GetWindowText,@hEditProcess,addr @szBuf,1024
			;��ȡ���̾��
			invoke GetDestProcessHandle,addr @szBuf
			mov @hDestProc,eax
			
			;��ȡ���ı��Ի����е����ݵ�@injectcodeBuf
			lea eax,@injectcodeBuf
			mov @es.dwCookie,eax
			push offset _EditstreamcallbackProc
			pop @es.pfnCallback
			mov @es.dwError,0
			
			invoke GetDlgItem,hwnd,IDC_CODE
			mov @hRichEdit,eax
			invoke _ZeroMem,addr @injectcodeBuf,1024

			;��ȡ���ı����ݣ�ͨ���ص����Ƹ�@injectcodeBuf������
			invoke SendMessage,@hRichEdit,EM_STREAMOUT,SF_TEXT,addr @es
			
			;��ȡ���ı����ݴ�С���ַ���
			mov @gtl.flags,GTL_NUMBYTES
			invoke SendMessage,@hRichEdit,EM_GETTEXTLENGTHEX,addr @gtl,0
			mov @editTextLength,eax
			
			;�򻺳���������һ���س��ַ�\n
			mov eax,@editTextLength
			lea esi,@injectcodeBuf
			mov byte ptr [eax + esi],0dh

			;ע�����
			invoke _InjectProcCode,@hDestProc,addr @injectcodeBuf,@editTextLength
			

			
		.endif
		jmp _do
	.else
		jmp _do_false
	.endif
_do:
	popad
	mov eax,TRUE
	ret
_do_false:	
	popad
	xor eax,eax
	ret
dlgProc_main endp

dialog_main proc
	local @dwRet:dword
	local @hRichEdit:dword
	local @hDlg
	local @msg
	pushad
	;�����Ի���
	invoke GetModuleHandle,NULL
	mov hInstance,eax

	invoke LoadLibrary,offset szDllEdit
	mov @hRichEdit,eax
	
	
	invoke DialogBoxParam,NULL,IDD_DLG_MAIN,NULL,offset dlgProc_main,NULL
	

	popad
	ret
dialog_main endp

start:
	invoke dialog_main
	invoke ExitProcess,0
end start