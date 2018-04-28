// Source: https://gist.github.com/simonwagner/10271224

#include <stdlib.h>
#include <string.h>

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
			  c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#include "taintgrind.h"

int
dtls1_process_heartbeat(char *p)//SSL *s)
       {
       unsigned char /**p = &s->s3->rrec.data[0], */*pl;
       unsigned short hbtype;
       unsigned int payload;
       unsigned int padding = 16; /* Use minimum padding */

       /* Read type and payload length first */
       hbtype = *p++;
       //! extracting the length of the payload from the heartbeat request package
       n2s(p, payload);
       pl = p;

       //if (s->msg_callback)
       //        s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
       //                &s->s3->rrec.data[0], s->s3->rrec.length,
       //                s, s->msg_callback_arg);

       if (hbtype == 2) //TLS1_HB_REQUEST)
               {
               unsigned char *buffer, *bp;
               int r;

               /* Allocate memory for the response, size is 1 byte
                * message type, plus 2 bytes payload length, plus
                * payload, plus padding
                */
               buffer = /*OPENSSL_*/malloc(1 + 2 + payload + padding);
               bp = buffer;

               /* Enter response type, length and copy payload */
               *bp++ = 0; //TLS1_HB_RESPONSE;
               s2n(payload, bp);
               //! Trying to copy payload from request into response package
               //! Note that payload might actually specify a length that is greater
               //! than the length of the request package, therefore memcpy will
               //! copy the memory behind the package into the response package.
               //! This will allow the hacker to extract application data
               //! This error gets repeated several times...
               memcpy(bp, pl, payload); //! do you want to get hacked? because that is how you get hacked
               /* Random padding */
               //RAND_pseudo_bytes(p, padding);

               //r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

               //if (r >= 0 && s->msg_callback)
               //        s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
               //                buffer, 3 + payload + padding,
               //                s, s->msg_callback_arg);

               /*OPENSSL_*/free(buffer);

               if (r < 0)
                       return r;
               }
       else if (hbtype == 1) //TLS1_HB_RESPONSE)
               {
               unsigned int seq;

               /* We only send sequence numbers (2 bytes unsigned int),
                * and 16 random bytes, so we just try to read the
                * sequence number */
               n2s(pl, seq);

               //if (payload == 18 && seq == s->tlsext_hb_seq)
               //        {
               //        dtls1_stop_timer(s);
               //        s->tlsext_hb_seq++;
               //        s->tlsext_hb_pending = 0;
               //        }
               }

       return 0;
       }

int main () {
    char data[8] = {2,0,4,2,2,2,2,2};

    TNT_TAINT(data, sizeof(data));
    //TNT_START_PRINT();

    dtls1_process_heartbeat(data);

    //TNT_STOP_PRINT();

    return 0;
}   
