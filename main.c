// Ronixz Cast - PRIMER PASO (Optimizado y Compilable)
// Hace que la PS4 se anuncie en la red como destino AirPlay.
// Solucionado error de sceNetSelect usando polling de baja latencia (20ms).

#include <orbis/libkernel.h>
#include <orbis/Sysmodule.h>
#include <orbis/Net.h>
#include <orbis/NetCtl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef ORBIS_NET_SOL_SOCKET
#define ORBIS_NET_SOL_SOCKET 0xffff
#endif
#ifndef ORBIS_NET_SO_NBIO
#define ORBIS_NET_SO_NBIO 0x1200
#endif
#ifndef ORBIS_NET_SO_REUSEADDR
#define ORBIS_NET_SO_REUSEADDR 4
#endif

typedef struct {
    uint8_t  sin_len;
    uint8_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint16_t sin_vport;
    char     sin_zero[6];
} MiSockaddrIn;

#define NOMBRE_RESPALDO "Ronixz PS4"
static char host_local[64];
static uint16_t puerto = 7000;

static char ps4_ip[16]   = "0.0.0.0";
static char nombre[48]   = NOMBRE_RESPALDO;
static char n_airplay[96];

// ---------- aviso en pantalla de la PS4 ----------
typedef struct {
    int type; int req_id; int priority; int msg_id; int target_id; int user_id;
    int unk1; int unk2; int app_id; int error_num; int unk3;
    char use_icon_image_uri; char message[1024]; char icon_uri[1024]; char unk[1024];
} NotifReq;

static void aviso(const char* texto) {
    NotifReq n;
    memset(&n, 0, sizeof(n));
    n.type = 0;
    n.use_icon_image_uri = 1;
    n.target_id = -1;
    strncpy(n.message, texto, sizeof(n.message) - 1);
    strcpy(n.icon_uri, "cxml://psnotification/tex_icon_system");
    sceKernelSendNotificationRequest(0, (OrbisNotificationRequest*)&n, sizeof(n), 0);
}

// ---------- armar el mensaje mDNS ----------
static uint8_t pkt[1200];
static int plen;

static void w8(uint8_t v)   { pkt[plen++] = v; }
static void w16(uint16_t v) { w8(v >> 8); w8(v & 255); }
static void w32(uint32_t v) { w16(v >> 16); w16(v & 65535); }

static void wname(const char* n) {
    while (*n) {
        const char* d = strchr(n, '.');
        int l = d ? (int)(d - n) : (int)strlen(n);
        w8((uint8_t)l);
        memcpy(pkt + plen, n, l);
        plen += l;
        n += l;
        if (*n == '.') n++;
    }
    w8(0);
}

static void txt(const char* s) {
    int l = (int)strlen(s);
    w8((uint8_t)l);
    memcpy(pkt + plen, s, l);
    plen += l;
}

static void rec_start(const char* name, uint16_t type, uint16_t cls, int* lenpos) {
    wname(name); w16(type); w16(cls); w32(120);
    *lenpos = plen;
    w16(0);
}

static void rec_end(int lenpos) {
    int l = plen - lenpos - 2;
    pkt[lenpos] = (uint8_t)(l >> 8);
    pkt[lenpos + 1] = (uint8_t)(l & 255);
}

static void armar(void) {
    int p, a, b, c, d;
    sscanf(ps4_ip, "%d.%d.%d.%d", &a, &b, &c, &d);
    snprintf(n_airplay, sizeof(n_airplay), "%s._airplay._tcp.local", nombre);

    plen = 0;
    w16(0); w16(0x8400); w16(0); w16(4); w16(0); w16(0); 

    rec_start("_airplay._tcp.local", 12, 1, &p);   
    wname(n_airplay);
    rec_end(p);

    rec_start(n_airplay, 33, 0x8001, &p);          
    w16(0); w16(0); w16(puerto);
    wname(host_local);
    rec_end(p);

    rec_start(n_airplay, 16, 0x8001, &p);          
    txt("deviceid=AA:BB:CC:DD:EE:01");
    txt("features=0x5A7FFFF7,0x1E");
    txt("model=AppleTV3,2");
    txt("srcvers=220.68");
    rec_end(p);

    rec_start(host_local, 1, 0x8001, &p);                
    w8(a); w8(b); w8(c); w8(d);
    rec_end(p);
}

// ---------- historial ----------
static char historial[4][120];
static int total_hist = 0;

static void anotar(const char* linea) {
    strncpy(historial[total_hist % 4], linea, 119);
    historial[total_hist % 4][119] = 0;
    total_hist++;
    FILE* f = fopen("/data/ronixz_cast.log", "a");
    if (f) { fprintf(f, "%s\n", linea); fclose(f); }
}

// ---------- responder al iPhone ----------
static void sacar_cseq(const char* buf, char* out, int max) {
    strcpy(out, "0");
    const char* p = strstr(buf, "CSeq:");
    if (!p) return;
    p += 5;
    while (*p == ' ') p++;
    int k = 0;
    while (*p && *p != '\r' && *p != '\n' && k < max - 1) out[k++] = *p++;
    out[k] = 0;
}

static void enviar_bin(int c, const char* estado, const char* cseq, const char* tipo, const char* datos, int bl) {
    char head[300];
    int hl = snprintf(head, sizeof(head),
        "RTSP/1.0 %s\r\nServer: AirTunes/220.68\r\nCSeq: %s\r\n%sContent-Length: %d\r\n\r\n",
        estado, cseq, tipo, bl);
    sceNetSend(c, head, hl, 0);
    if (bl > 0) sceNetSend(c, datos, bl, 0);
}

static void enviar(int c, const char* estado, const char* cseq, const char* tipo, const char* cuerpo) {
    enviar_bin(c, estado, cseq, tipo, cuerpo, cuerpo ? (int)strlen(cuerpo) : 0);
}

static void responder(int c, const char* buf) {
    char cseq[16];
    sacar_cseq(buf, cseq, sizeof(cseq));
    
    if (strncmp(buf, "GET /info", 9) == 0) {
        char cuerpo[1024];
        snprintf(cuerpo, sizeof(cuerpo),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><dict>\n"
            "<key>deviceid</key><string>AA:BB:CC:DD:EE:01</string>\n"
            "<key>macAddress</key><string>AA:BB:CC:DD:EE:01</string>\n"
            "<key>features</key><integer>130367356919</integer>\n"
            "<key>model</key><string>AppleTV3,2</string>\n"
            "<key>name</key><string>%s</string>\n"
            "<key>sourceVersion</key><string>220.68</string>\n"
            "<key>statusFlags</key><integer>4</integer>\n"
            "<key>pi</key><string>2e388006-13ba-4041-9a67-25dd4a43d536</string>\n"
            "<key>vv</key><integer>2</integer>\n"
            "</dict></plist>\n", nombre);
        enviar(c, "200 OK", cseq, "Content-Type: text/x-apple-plist+xml\r\n", cuerpo);
    } else if (strncmp(buf, "POST /pair-setup", 16) == 0) {
        char d[32];
        for (int i = 0; i < 32; i++) d[i] = (char)((i * 7 + 1) & 255);
        enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", d, 32);
    } else if (strncmp(buf, "POST /pair-verify", 17) == 0) {
        char d[96];
        for (int i = 0; i < 96; i++) d[i] = (char)((i * 5 + 3) & 255);
        enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", d, 96);
    } else if (strncmp(buf, "POST /fp-setup", 14) == 0) {
        char d[142];
        for (int i = 0; i < 142; i++) d[i] = (char)((i * 3 + 9) & 255);
        enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", d, 142);
    } else if (strncmp(buf, "OPTIONS", 7) == 0) {
        enviar(c, "200 OK", cseq, "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET\r\n", NULL);
    } else {
        enviar(c, "200 OK", cseq, "", NULL);
    }
}

// ---------- programa principal ----------
int main(void) {
    sceSysmoduleLoadModuleInternal(ORBIS_SYSMODULE_INTERNAL_NET);
    sceNetInit();
    sceNetPoolCreate("ronixz", 64 * 1024, 0);

    sceNetCtlInit();
    OrbisNetCtlInfo info;

    memset(&info, 0, sizeof(info));
    if (sceNetCtlGetInfo(ORBIS_NET_CTL_INFO_IP_ADDRESS, &info) == 0) {
        strncpy(ps4_ip, info.ip_address, sizeof(ps4_ip) - 1);
    } else {
        aviso("Ronixz Cast: no pude detectar la IP.");
        return 1;
    }

    memset(&info, 0, sizeof(info));
    if (sceNetCtlGetInfo(ORBIS_NET_CTL_INFO_DHCP_HOSTNAME, &info) == 0 && info.dhcp_hostname[0] != 0) {
        strncpy(nombre, info.dhcp_hostname, sizeof(nombre) - 1);
        nombre[sizeof(nombre) - 1] = 0;
        for (char* q = nombre; *q; q++) if (*q == '.') *q = '-';
    }

    {
        char limpio[40];
        int k = 0;
        for (const char* q = nombre; *q && k < 38; q++) {
            char ch = *q;
            if (ch >= 'A' && ch <= 'Z') ch = ch - 'A' + 'a';
            if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') limpio[k++] = ch;
        }
        limpio[k] = 0;
        if (k == 0) strcpy(limpio, "ps4");
        snprintf(host_local, sizeof(host_local), "%s.local", limpio);
    }

    int ts = sceNetSocket("airplay", ORBIS_NET_AF_INET, ORBIS_NET_SOCK_STREAM, 0);
    if (ts >= 0) {
        MiSockaddrIn ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_len = sizeof(ta);
        ta.sin_family = ORBIS_NET_AF_INET;
        ta.sin_port = 0; 
        if (sceNetBind(ts, (OrbisNetSockaddr*)&ta, sizeof(ta)) == 0) {
            unsigned int tl = sizeof(ta);
            if (sceNetGetsockname(ts, (OrbisNetSockaddr*)&ta, &tl) == 0) {
                puerto = sceNetNtohs(ta.sin_port);
            }
            sceNetListen(ts, 5);
        }
        // Socket NO bloqueante 
        int uno2 = 1;
        sceNetSetsockopt(ts, ORBIS_NET_SOL_SOCKET, ORBIS_NET_SO_NBIO, &uno2, sizeof(uno2));
    }

    int s = sceNetSocket("mdns", ORBIS_NET_AF_INET, ORBIS_NET_SOCK_DGRAM, 0);
    if (s < 0) { aviso("Ronixz Cast: no pude abrir la red"); return 1; }

    int uno = 1;
    sceNetSetsockopt(s, ORBIS_NET_SOL_SOCKET, ORBIS_NET_SO_REUSEADDR, &uno, sizeof(uno));

    MiSockaddrIn dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_len = sizeof(dest);
    dest.sin_family = ORBIS_NET_AF_INET;
    dest.sin_port = sceNetHtons(5353);
    {
        uint8_t* ab = (uint8_t*)&dest.sin_addr; 
        ab[0] = 224; ab[1] = 0; ab[2] = 0; ab[3] = 251;
    }

    armar();

    char msg[128];
    snprintf(msg, sizeof(msg), "Ronixz Cast listo. IP: %s, puerto: %d", ps4_ip, (int)puerto);
    aviso(msg);

    int cli[4] = { -1, -1, -1, -1 };
    int ocio[4] = { 0, 0, 0, 0 };
    int vuelta = 0;

    for (;;) {
        // Anunciar mDNS a la red cada ~5 segundos (250 vueltas * 20ms = 5000ms)
        if (vuelta % 250 == 0) {
            sceNetSendto(s, pkt, plen, 0, (OrbisNetSockaddr*)&dest, sizeof(dest));
        }
        vuelta++;

        // Aceptar nuevas conexiones RTSP del iPhone
        if (ts >= 0) {
            MiSockaddrIn ca;
            unsigned int cl = sizeof(ca);
            memset(&ca, 0, sizeof(ca));
            int nuevo_c = sceNetAccept(ts, (OrbisNetSockaddr*)&ca, &cl);
            
            if (nuevo_c >= 0) {
                int uno3 = 1;
                sceNetSetsockopt(nuevo_c, ORBIS_NET_SOL_SOCKET, ORBIS_NET_SO_NBIO, &uno3, sizeof(uno3));
                
                int puesto = -1;
                for (int i = 0; i < 4; i++) {
                    if (cli[i] < 0) { puesto = i; break; }
                }
                if (puesto < 0) { 
                    sceNetSocketClose(cli[0]); 
                    puesto = 0; 
                }
                cli[puesto] = nuevo_c;
                ocio[puesto] = 0;
            }
        }

        // Leer peticiones de los iPhones conectados
        for (int i = 0; i < 4; i++) {
            if (cli[i] < 0) continue;
            
            char buf[4096];
            memset(buf, 0, sizeof(buf));
            int n = sceNetRecv(cli[i], buf, sizeof(buf) - 1, 0);
            
            if (n > 0) {
                ocio[i] = 0;
                
                // Asegurar lectura de Content-Length
                char* body_start = strstr(buf, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    char* cl_ptr = strstr(buf, "Content-Length:");
                    if (cl_ptr) {
                        int cl_len = atoi(cl_ptr + 15);
                        int current_body_len = n - (body_start - buf);
                        
                        while (current_body_len < cl_len && n < (int)sizeof(buf) - 1) {
                            int extra = sceNetRecv(cli[i], buf + n, sizeof(buf) - 1 - n, 0);
                            if (extra > 0) {
                                n += extra;
                                current_body_len += extra;
                            } else if (extra < 0) {
                                sceKernelUsleep(5000); // Pequeña pausa de 5ms si bloquea
                            }
                        }
                    }
                }

                // Registrar y responder
                char linea[90];
                int k = 0;
                for (int j = 0; j < n && k < 80 && buf[j] != '\r' && buf[j] != '\n'; j++) {
                    unsigned char ch = (unsigned char)buf[j];
                    linea[k++] = (ch >= 32 && ch < 127) ? (char)ch : '?';
                }
                linea[k] = 0;
                
                char log_msg[240];
                snprintf(log_msg, sizeof(log_msg), "iPhone pidio: %s", linea);
                anotar(log_msg);
                
                responder(cli[i], buf);
                
            } else if (n == 0) {
                // Conexión cerrada por el iPhone
                sceNetSocketClose(cli[i]);
                cli[i] = -1;
            } else {
                // n < 0 (no hay datos)
                ocio[i]++;
                if (ocio[i] > 750) { // ~15 segundos inactivo (750 * 20ms)
                    sceNetSocketClose(cli[i]);
                    cli[i] = -1;
                }
            }
        }
        
        // Latencia bajada al minimo (20 milisegundos en lugar de 200)
        sceKernelUsleep(20000);
    }
    return 0;
}
