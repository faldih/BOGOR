;---------------------------------------------------------------------------------------------------
; @AUTHOR Muhammad Quwais Safutra
; @Copyright 2018BES
;---------------------------------------------------------------------------------------------------

CODE    ENDS

CONST   SEGMENT PUBLIC BYTE

        EXTRN   USER_PROC_PDB:WORD,STACK:BYTE,CSSAVE:WORD,DSSAVE:WORD
        EXTRN   SPSAVE:WORD,IPSAVE:WORD,LINEBUF:BYTE,QFLAG:BYTE
        EXTRN   NEWEXEC:BYTE,HEADSAVE:WORD,LBUFSIZ:BYTE,BACMES:BYTE
        EXTRN   BADVER:BYTE,ENDMES:BYTE,CARRET:BYTE,ParityMes:BYTE

        IF  IBMVER
        EXTRN   DSIZ:BYTE,NOREGL:BYTE,DISPB:WORD
        ENDIF

        IF      SYSVER
        EXTRN   CONFCB:BYTE,POUT:DWORD,COUT:DWORD,CIN:DWORD,IOBUFF:BYTE
        EXTRN   IOADDR:DWORD,IOCALL:BYTE,IOCOM:BYTE,IOSTAT:WORD,IOCNT:WORD
        EXTRN   IOSEG:WORD,COLPOS:BYTE,BADDEV:BYTE,BADLSTMES:BYTE
        EXTRN   LBUFFCNT:BYTE,PFLAG:BYTE
        ENDIF

CONST   ENDS

DATA    SEGMENT PUBLIC BYTE

        EXTRN   PARSERR:BYTE,DATAEND:WORD,ParityFlag:BYTE,DISADD:BYTE
        EXTRN   ASMADD:BYTE,DEFDUMP:BYTE,BYTEBUF:BYTE

DATA    ENDS

DG      GROUP   CODE,CONST,DATA


CODE    SEGMENT PUBLIC 'CODE'
ASSUME  CS:DG,DS:DG,ES:DG,SS:DG

        PUBLIC  RESTART,SET_TERMINATE_VECTOR,DABORT,TERMINATE,COMMAND
        PUBLIC  FIND_DEBUG,CRLF,BLANK,TAB,OUT,INBUF,SCANB,SCANP
        PUBLIC  PRINTMES,RPRBUF,HEX,OUTSI,OUTDI,OUT16,DIGIT,BACKUP,RBUFIN

        IF  SYSVER
        PUBLIC  SETUDEV,DEVIOCALL
        EXTRN   DISPREG:NEAR,IN:NEAR
        ENDIF

        EXTRN   PERR:NEAR,COMPARE:NEAR,DUMP:NEAR,ENTER:NEAR,FILL:NEAR
        EXTRN   GO:NEAR,INPUT:NEAR,LOAD:NEAR,MOVE:NEAR,NAME:NEAR
        EXTRN   REG:NEAR,SEARCH:NEAR,DWRITE:NEAR,UNASSEM:NEAR,ASSEM:NEAR
        EXTRN   OUTPUT:NEAR,ZTRACE:NEAR,TRACE:NEAR,GETHEX:NEAR,GETEOL:NEAR

        EXTRN   PREPNAME:NEAR,DEFIO:NEAR,SKIP_FILE:NEAR,DEBUG_FOUND:NEAR
        EXTRN   TrapParity:NEAR,ReleaseParity:NEAR

        ORG     100H

START:
DEBUG:
        JMP     SHORT DSTRT

HEADER DB       "Vers 2.30"

DSTRT:
DOSVER_HIGH     EQU  0200H              
        MOV     AH,GET_VERSION
        INT     21H
        XCHG    AH,AL                   
        CMP     AX,DOSVER_HIGH
        JAE     OKDOS
GOTBADDOS:
        MOV     DX,OFFSET DG:BADVER
        MOV     AH,STD_CON_STRING_OUTPUT
        INT     21H
        INT     20H

OKDOS:
        CALL    TrapParity              
        MOV     AH,GET_CURRENT_PDB
        INT     21H
        MOV     [USER_PROC_PDB],BX      

        IF      SYSVER
        MOV     [IOSEG],CS
        ENDIF

        MOV     SP,OFFSET DG:STACK
        MOV     [PARSERR],AL
        MOV     AH,GET_IN_VARS
        INT     21H


        IF      SYSVER
        LDS     SI,ES:[BX.BCON]
        MOV     WORD PTR CS:[CIN+2],DS
        MOV     WORD PTR CS:[CIN],SI
        MOV     WORD PTR CS:[COUT+2],DS
        MOV     WORD PTR CS:[COUT],SI
        PUSH    CS
        POP     DS
        MOV     DX,OFFSET DG:CONFCB
        MOV     AH,FCB_OPEN
        INT     21H
        OR      AL,AL
        JZ      GOTLIST
        MOV     DX,OFFSET DG:BADLSTMES
        CALL    RPRBUF
        CALL    RBUFIN
        CALL    CRLF
        MOV     CL,[LBUFFCNT]
        OR      CL,CL
        JZ      NOLIST1                 
        XOR     CH,CH
        MOV     DI,OFFSET DG:(CONFCB + 1)
        MOV     SI,OFFSET DG:LINEBUF
        REP     MOVSB
        MOV     DX,OFFSET DG:CONFCB
        MOV     AH,FCB_OPEN
        INT     21H
        OR      AL,AL
        JZ      GOTLIST                 
        MOV     DX,OFFSET DG:BADDEV
        CALL    RPRBUF
NOLIST1:
        MOV     WORD PTR [POUT+2],CS
        MOV     WORD PTR [POUT],OFFSET DG:LONGRET
        JMP     NOLIST

XXX     PROC FAR
LONGRET:RET
XXX     ENDP
        ENDIF

GOTLIST:
        IF      SYSVER
        MOV     SI,DX
        LDS     SI,DWORD PTR DS:[SI.fcb_FIRCLUS]
        MOV     WORD PTR CS:[POUT+2],DS
        MOV     WORD PTR CS:[POUT],SI
        ENDIF
NOLIST:
        MOV     AX,CS
        MOV     DS,AX
        MOV     ES,AX
		
		
		
		
        CALL    SET_TERMINATE_VECTOR

        IF      SETCNTC
        MOV     AL,23H                 
        MOV     DX,OFFSET DG:DABORT
        INT     21H
        ENDIF
