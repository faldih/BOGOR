;--------------------------------------------------------------------------------
;  @AUTHOR  : Ditiyo Pangestu
;  @Copyright BES-2019
;--------------------------------------------------------------------------------


PAGE
CONST   SEGMENT PUBLIC BYTE

        PUBLIC  HECODE,SWITCHAR,NOISY,DOFIX,CONBUF,ORPHCNT,ORPHSIZ,DOFIX
        PUBLIC  HIDCNT,HIDSIZ,DIRCNT,DIRSIZ,FILCNT,FILSIZ,BADSIZ,LCLUS
        PUBLIC  DOTENT,HAVFIX,SECONDPASS,NUL,ALLFILE,PARSTR,ERRSUB,LCLUS
        PUBLIC  DIRTYFAT,BADSIZ,DDOTENT,CROSSCNT,ORPHFCB,ORPHEXT,ALLDRV
        PUBLIC  FRAGMENT,USERDIR,DIRBUF,USERDIR,FIXMFLG,DOTMES,DIRCHAR

        EXTRN   IDMES1:BYTE,IDPOST:BYTE,VNAME:BYTE,MONTAB:BYTE
        EXTRN   TCHAR:BYTE,BADREAD_PRE:BYTE,BADREAD_POST:BYTE
        EXTRN   CRLF:BYTE,BADVER:BYTE,BADSUBDIR:BYTE,CENTRY:BYTE
        EXTRN   BADDRV:BYTE,BADCD:BYTE,BADRDMES:BYTE,OPNERR:BYTE
        EXTRN   CONTAINS:BYTE,EXTENTS:BYTE,NOEXTENTS:BYTE
        EXTRN   BADDRVM:BYTE,BADDRVM2:BYTE,BADIDBYT:BYTE


DIRBUF  LABEL   BYTE                    
VOLID   DB      -1,0,0,0,0,0,8          
VOLNAM  DB      0,"???????????"
        DB      25 DUP(0)

ALLFILE DB      -1,0,0,0,0,0,1EH        
ALLDRV  DB      0,"???????????"
        DB      25 DUP (?)

ORPHFCB DB      0,"FILE0000"
ORPHEXT DB      "CHK"
        DB      25 DUP (?)

SWITCHAR DB     "-"
ROOTSTR LABEL   BYTE
DIRCHAR DB      "/"
NUL     DB      0
PARSTR  DB      "..",0
DOTMES  DB      ".",0
DOTENT  DB      ".          "
DDOTENT DB      "..         "
HECODE  DB      ?
FIXMFLG DB      0                       
ERRSUB  DW      0                       
FRAGMENT DB     0                       
DIRTYFAT DB     0                       
DIRCNT  DW      0                      
DIRSIZ  DW      0                       
FILCNT  DW      0                       
FILSIZ  DW      0                       
HIDCNT  DW      0                       
HIDSIZ  DW      0                       
BADSIZ  DW      0                       
ORPHCNT DW      0                       
ORPHSIZ DW      0                       
LCLUS   DW      0                       
DISPFLG DB      0                       
CROSSCNT DW     0                       
SECONDPASS DB   0                       
HAVFIX  DB      0                       
DOFIX   DB      0                       
NOISY   DB      0                       
USERDIR DB      "/",0                   
        DB      (DIRSTRLEN-1) DUP (?)
CONBUF  DB      15,0                    
        DB      15 DUP (?)

CONST   ENDS

SUBTTL  Un-initialized Data
PAGE
DATA    SEGMENT PUBLIC WORD

        PUBLIC  ZEROTRUNC,NAMBUF,MCLUS,THISDPB,STACKLIM,ERRCNT
        PUBLIC  SRFCBPT,ISCROSS,CSIZE,DSIZE,SSIZE,FAT,FATMAP
        PUBLIC  HARDCH,CONTCH,USERDEV,SECBUF,DOTSNOGOOD

HARDCH  DD      ?                       
CONTCH  DD      ?                       
THISDPB DD      ?                       
USERDEV DB      ?                       
CSIZE   DB      ?                       
SSIZE   DW      ?                       
DSIZE   DW      ?                       
MCLUS   DW      ?                       
NAMBUF  DB      14 DUP (?)              
DOTSNOGOOD DB   ?                       
ZEROTRUNC DB    ?                       
ISCROSS DB      ?                       
OLDCLUS DW      ?
SRFCBPT DW      ?
FATMAP  DW      OFFSET DG:FAT           
SECBUF  DW      ?                       
ERRCNT  DB      ?                      
STACKLIM DW     ?                       

INTERNATVARS    internat_block <>
                DB      (internat_block_max - ($ - INTERNATVARS)) DUP (?)

FAT     LABEL   WORD
DATA    ENDS


SUBTTL  Start of CHKDSK

CODE    SEGMENT PUBLIC
ASSUME  CS:DG,DS:DG,ES:DG,SS:DG

        PUBLIC  SUBERRP,DOTCOMBMES,FIGREC,FCB_TO_ASCZ,PRTCHR,EPRINT
        PUBLIC  PRINT,DOCRLF,DISP16BITS,DISP32BITS,DISPCLUS,CHECKFILES

        EXTRN   RDSKERR:NEAR,SETSWITCH:NEAR,PROMPTYN:NEAR,REPORT:NEAR
        EXTRN   PRINTCURRDIRERR:NEAR,PRINTTHISEL2:NEAR,CHECKERR:NEAR
        EXTRN   INT_23:NEAR,INT_24:NEAR,FINDCHAIN:NEAR,DONE:NEAR,AMDONE:NEAR
        EXTRN   FATAL:NEAR,DIRPROC:NEAR,CHKMAP:NEAR,CHKCROSS:NEAR,UNPACK:NEAR

        ORG     100H

CHKDSK:
        JMP     SHORT CHSTRT
