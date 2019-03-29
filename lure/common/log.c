#include "log.h"
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include "util.h"

int logger_init(const char* fileName){
    assert(NULL != fileName);
    memset(FILE_LOG, 0, sizeof(FILE_LOG));
	strcpy(FILE_LOG, LOG_PATH);
    strcat(FILE_LOG, fileName);

	return 0;
}

void log_hex(unsigned char *msg, int len, char *tips){
    FILE *fp = NULL;
    char FILE_LOG[100]="/tmp/hex_data.log";
    fp = fopen(FILE_LOG, "a+");
    if(!fp){
        perror("in logger function, can't open file with mode a+:\n");
        printf("length is %d. file name is %s\n", len, FILE_LOG);
        return;
    }

    int file_size = 0;
    if(0 == fseek(fp, 0, SEEK_END)){
        file_size = ftell(fp);
        if(MAX_SIZE <= file_size){
            int i,j;
            FILE *fp_tmp = NULL;
            char dst_file[strlen(FILE_LOG)+5];
            char src_file[strlen(FILE_LOG)+5];
            memset(dst_file, 0, sizeof(dst_file));
            memset(src_file, 0, sizeof(src_file));
            char num[2]={0};
            char num_tmp[2]={0};
            for(i=1; i< MAX_NUMBER; i++){
                strcpy(dst_file, FILE_LOG);
                sprintf(num, "%d", i);
                strcat(dst_file, ".");
                strcat(dst_file, num);
                fp_tmp = fopen(dst_file, "r");
                if(fp_tmp){
                    fclose(fp_tmp);
                }else{
                    break;
                }
            }
            if(MAX_NUMBER == i){
                --i;
            }
            for(j=i-1;j>=0;j--){
                strcpy(src_file,FILE_LOG);
                strcpy(dst_file, FILE_LOG);
                if(j > 0){
                    sprintf(num, "%d", j);
                    strcat(src_file, ".");
                    strcat(src_file, num);
                }
                sprintf(num_tmp, "%d", j+1);
                strcat(dst_file, ".");
                strcat(dst_file, num_tmp);
                //Backup(dst_file, src_file);
                change_name(dst_file, src_file);
            }
            fclose(fp);
            fp = NULL;
            fp = fopen(FILE_LOG,"w");
            if(!fp){
                perror("in logger function, can't open file with mode w:\n");
                printf("length is %d. file name is %s\n", strlen(FILE_LOG), FILE_LOG);
                return;
            }
        }
    }else{
        perror("logger_init:\n");
        fclose(fp);
        return;
    }
    char time_Buf[20] = {0};
    time_t timer = time(NULL);
    strftime(time_Buf, sizeof(time_Buf), "%Y-%m-%d %H:%M:%S", localtime(&timer));
    fprintf(fp, "%s %s in function %s line %d=>%s\n", time_Buf, __FILE__, __FUNCTION__, __LINE__, tips);

    int i=0;
    while(i<len){
        fprintf(fp, "%02X ", *(msg+i++));
    }
    fprintf(fp, "\n");
    fclose(fp);
    return;
}

void logger(const char* level, const char* file, const char* function, int line, const char* msg, ...){
    assert(NULL != msg);
    char sprint_buf[MSG_MAX_LEN];
    va_list ap;
    va_start(ap, msg);
    memset(sprint_buf, 0, sizeof(sprint_buf));
    log_buf(sprint_buf, msg, ap);
    va_end(ap);
    char time_Buf[20] = {0};
    time_t timer = time(NULL);
    strftime(time_Buf, sizeof(time_Buf), "%Y-%m-%d %H:%M:%S", localtime(&timer));
    if( 1 == APPENDER_TYPE){
        //output to console
        printf("%s %s %s in function %s line %d=>%s\n", time_Buf, level, file, function, line, sprint_buf);
        return;
    }

    FILE *fp = NULL;
    fp = fopen(FILE_LOG,"a+");
    if(!fp){
        perror("in logger function, can't open file with mode a+:\n");
        printf("length is %d. file name is %s\n", strlen(FILE_LOG), FILE_LOG);
        return;
    }
    int file_size = 0;
    if(0 == fseek(fp, 0, SEEK_END)){
        file_size = ftell(fp);
        if(MAX_SIZE <= file_size){
            int i,j;
            FILE *fp_tmp = NULL;
            char dst_file[strlen(FILE_LOG)+5];
            char src_file[strlen(FILE_LOG)+5];
            memset(dst_file, 0, sizeof(dst_file));
            memset(src_file, 0, sizeof(src_file));
            char num[2]={0};
            char num_tmp[2]={0};
            for(i=1; i< MAX_NUMBER; i++){
                strcpy(dst_file, FILE_LOG);
                sprintf(num, "%d", i);
                strcat(dst_file, ".");
                strcat(dst_file, num);
                fp_tmp = fopen(dst_file, "r");
                if(fp_tmp){
                    fclose(fp_tmp);
                }else{
                    break;
                }
            }
            if(MAX_NUMBER == i){
                --i;
            }
            for(j=i-1;j>=0;j--){
                strcpy(src_file,FILE_LOG);
                strcpy(dst_file, FILE_LOG);
                if(j > 0){
                    sprintf(num, "%d", j);
                    strcat(src_file, ".");
                    strcat(src_file, num);
                }
                sprintf(num_tmp, "%d", j+1);
                strcat(dst_file, ".");
                strcat(dst_file, num_tmp);
                //Backup(dst_file, src_file);
                change_name(dst_file, src_file);
            }
//            memset(dst_file, 0, sizeof(dst_file));
//            strcpy(dst_file, FILE_LOG);
//            strcat(dst_file, ".old");
//            Backup(dst_file, FILE_LOG);
            fclose(fp);
            fp = NULL;
            fp = fopen(FILE_LOG,"w");
            if(!fp){
                perror("in logger function, can't open file with mode w:\n");
                printf("length is %d. file name is %s\n", strlen(FILE_LOG), FILE_LOG);
                return;
            }
        }
    }else{
        perror("logger_init:\n");
        fclose(fp);
        return;
    }
    if(strlen(msg) > 0){
        memset(time_Buf, 0, sizeof(time_Buf));
        timer = time(NULL);
        //strptime("2010-11-15 10:39:30", "%Y-%m-%d %H:%M:%S", &tm_time);
        strftime(time_Buf, sizeof(time_Buf), "%Y-%m-%d %H:%M:%S", localtime(&timer));
        if(0 == APPENDER_TYPE){
            //output to file and console
            fprintf(fp, "%s %s %s in function %s line %d=>%s\n", time_Buf, level, file, function, line, sprint_buf);
            printf("%s %s %s in function %s line %d=>%s\n", time_Buf, level, file, function, line, sprint_buf);
        }else if(2 == APPENDER_TYPE){
            //output to file
            fprintf(fp, "%s %s %s in function %s line %d=>%s\n", time_Buf, level, file, function, line, sprint_buf);
        }
    }
    fclose(fp);
}

int change_name(const char *dstFile, const char *srcFile){
    char cmd[100] = {0};
    strcat(cmd, "mv ");
    strcat(cmd, srcFile);
    strcat(cmd, " ");
    strcat(cmd, dstFile);

    return system_shell(cmd);
}

int Backup(const char *dstFile, const char *srcFile){
	assert(NULL != dstFile || NULL != srcFile);

	char buf_in[LINE_SIZE];
	FILE *fp = NULL, *nfp = NULL;
	fp = fopen(srcFile, "r");
	if(NULL == fp){
		printf("Can't open %s", srcFile);
		return -1;
	}
	int file_len = 0;
	//SEEK_SET(beginning) SEEK_CUR(current position) SEEK_END
	if(0 == fseek(fp,0,SEEK_END)){
		file_len = ftell(fp);
	}else{
		fclose(fp);
		return -1;
	}

	char *file_buf = NULL;
	file_buf = (char *)malloc(file_len + 1);
	if(NULL == file_buf){
		printf("assign memory fail!");
		return -1;
	}
	memset(file_buf, 0, file_len + 1);

	if(0 ==fseek(fp, 0, SEEK_SET)){// seek to beginning of file
		while(!feof(fp) && fgets(buf_in, LINE_SIZE, fp)){
			strncat(file_buf, buf_in, strlen(buf_in));
		}
		file_buf[file_len + 1]='\0';

		nfp = fopen(dstFile, "w");
		if( NULL == nfp){
			return -1;
		}
		if(strlen(file_buf) > 0){
			fprintf(nfp, "%s", file_buf);
		}
		fclose(nfp);// release new file pointer
	}
	free(file_buf);
	fclose(fp);// release source file pointer
	return 1;
}

static int skip_atoi(const char **s){
        int i = 0;

        while (isdigit(**s))
                i = i * 10 + *((*s)++) - '0';
        return i;
}

static char *number(char *str, long num, int base, int size, int precision, int type){
        /* we are called with base 8, 10 or 16, only, thus don't need "G..."  */
        static const char digits[16] = "0123456789ABCDEF"; /* "GHIJKLMNOPQRSTUVWXYZ"; */

        char tmp[66];
        char c, sign, locase;
        int i;

        /* locase = 0 or 0x20. ORing digits or letters with 'locase'
         * produces same digits or (maybe lowercased) letters */
        locase = (type & SMALL);
        if (type & LEFT)
                type &= ~ZEROPAD;
        if (base < 2 || base > 36)
                return NULL;
        c = (type & ZEROPAD) ? '0' : ' ';
        sign = 0;
        if (type & SIGN) {
                if (num < 0) {
                        sign = '-';
                        num = -num;
                        size--;
                } else if (type & PLUS) {
                        sign = '+';
                        size--;
                } else if (type & SPACE) {
                        sign = ' ';
                        size--;
                }
        }
        if (type & SPECIAL) {
                if (base == 16)
                        size -= 2;
                else if (base == 8)
                        size--;
        }
        i = 0;
        if (num == 0)
                tmp[i++] = '0';
        else
                while (num != 0)
                        tmp[i++] = (digits[__do_div(num, base)] | locase);
        if (i > precision)
                precision = i;
        size -= precision;
        if (!(type & (ZEROPAD + LEFT)))
                while (size-- > 0)
                        *str++ = ' ';
        if (sign)
                *str++ = sign;
        if (type & SPECIAL) {
                if (base == 8)
                        *str++ = '0';
                else if (base == 16) {
                        *str++ = '0';
                        *str++ = ('X' | locase);
                }
        }
        if (!(type & LEFT))
                while (size-- > 0)
                        *str++ = c;
        while (i < precision--)
                *str++ = '0';
        while (i-- > 0)
                *str++ = tmp[i];
        while (size-- > 0)
                *str++ = ' ';
        return str;
}

int log_buf(char *buf, const char *fmt, va_list args){
  int len;
  unsigned long num;
  int i, base;
  char *str;
  char *s;

  int flags;            // Flags to number()

  int field_width;    // Width of output field
  int precision;    // Min. # of digits for integers; max number of chars for from string
  int qualifier;    // 'h', 'l', or 'L' for integer fields

  for (str = buf; *fmt; fmt++)
  {
    if (*fmt != '%')
    {
      *str++ = *fmt;
      continue;
    }

    // Process flags
    flags = 0;
repeat:
    fmt++; // This also skips first '%'
    switch (*fmt)
    {
      case '-': flags |= LEFT; goto repeat;
      case '+': flags |= PLUS; goto repeat;
      case ' ': flags |= SPACE; goto repeat;
      case '#': flags |= SPECIAL; goto repeat;
      case '0': flags |= ZEROPAD; goto repeat;
    }

    // Get field width
    field_width = -1;
    if (is_digit(*fmt))
      field_width = skip_atoi(&fmt);
    else if (*fmt == '*')
    {
      fmt++;
      field_width = va_arg(args, int);
      if (field_width < 0)
      {
        field_width = -field_width;
        flags |= LEFT;
      }
    }

    // Get the precision
    precision = -1;
    if (*fmt == '.')
    {
      ++fmt;
      if (is_digit(*fmt))
        precision = skip_atoi(&fmt);
      else if (*fmt == '*')
      {
        ++fmt;
        precision = va_arg(args, int);
      }
      if (precision < 0) precision = 0;
    }

    // Get the conversion qualifier
    qualifier = -1;
    if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L')
    {
      qualifier = *fmt;
      fmt++;
    }

    // Default base
    base = 10;

    switch (*fmt)
    {
      case 'c':
    if (!(flags & LEFT)) while (--field_width > 0) *str++ = ' ';
    *str++ = (unsigned char) va_arg(args, int);
    while (--field_width > 0) *str++ = ' ';
    continue;

      case 's':
    s = va_arg(args, char *);
    if (!s)    s = "<NULL>";
    len = strnlen(s, precision);
    int len_valid = MSG_MAX_LEN + buf - str - 100;
    if(len > len_valid){
        if(len_valid > 0){
            len = len_valid;
        }
        else{
            return str - buf;
        }
    }
    if (!(flags & LEFT)) while (len < field_width--) *str++ = ' ';
    for (i = 0; i < len; ++i) *str++ = *s++;
    while (len < field_width--) *str++ = ' ';
    continue;

      case 'p':
    if (field_width == -1)
    {
      field_width = 2 * sizeof(void *);
      flags |= ZEROPAD;
    }
    str = number(str, (unsigned long) va_arg(args, void *), 16, field_width, precision, flags);
    continue;

      case 'n':
    if (qualifier == 'l')
    {
      long *ip = va_arg(args, long *);
      *ip = (str - buf);
    }
    else
    {
      int *ip = va_arg(args, int *);
      *ip = (str - buf);
    }
    continue;

      // Integer number formats - set up the flags and "break"
      case 'o':
    base = 8;
    break;

      case 'x':
      case 'X':
    base = 16;
    break;

      case 'd':
      case 'i':
    flags |= SIGN;

      case 'u':
    break;

      default:
    if (*fmt != '%') *str++ = '%';
    if (*fmt)
      *str++ = *fmt;
    else
      --fmt;
    continue;
    }

    if (qualifier == 'l')
      num = va_arg(args, unsigned long);
    else if (qualifier == 'h')
    {
      if (flags & SIGN)
    	num = va_arg(args, short);
      else
   		num = va_arg(args, unsigned short);
    }
    else if (flags & SIGN)
      num = va_arg(args, int);
    else
      num = va_arg(args, unsigned int);

    str = number(str, num, base, field_width, precision, flags);
  }

  *str = '\0';
  return str - buf;
}
