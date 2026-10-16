// Ronixz Cast - PRIMER PASO (sin probar)
// Hace que la PS4 se anuncie en la red como destino AirPlay.
// Todavia NO recibe video: solo intenta aparecer en la lista de AirPlay.
// La IP, el nombre, el host y el puerto se detectan/eligen solos.

#include <orbis/libkernel.h>
#include <orbis/Sysmodule.h>
#include <orbis/Net.h>
#include <orbis/NetCtl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "tweetnacl.h"
#include "aes.h"
#include "tn.inc"   // codigo de tweetnacl (lo baja el compilador de GitHub)
#include "aes.inc"  // codigo de tiny-AES (lo baja el compilador de GitHub)

// Definiciones de red que OpenOrbis no trae (valores estandar de la PS4/FreeBSD)
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
static char host_local[64];      // se arma solo a partir del nombre de la consola
static uint16_t puerto = 7000;   // se reemplaza por un puerto libre que elige la PS4

static char ps4_ip[16]   = "0.0.0.0";
static char nombre[48]   = NOMBRE_RESPALDO;
static char n_airplay[96];   // "<nombre>._airplay._tcp.local"

// ---------- criptografia (emparejamiento de AirPlay) ----------
static unsigned char ed_pk[32], ed_sk[64];   // llave "de identidad" de la PS4

void randombytes(unsigned char* x, unsigned long long n) {
    static uint64_t st = 0;
    if (st == 0) {
        unsigned int lo, hi;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        st = (((uint64_t)hi << 32) | lo) ^ 0x9E3779B97F4A7C15ULL;
    }
    for (unsigned long long i = 0; i < n; i++) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        x[i] = (unsigned char)(st >> 24);
    }
}

static void a_hex(const unsigned char* in, int n, char* out) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2 * i] = H[in[i] >> 4]; out[2 * i + 1] = H[in[i] & 15]; }
    out[2 * n] = 0;
}

static void a_b64(const unsigned char* in, int n, char* out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? T[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? T[v & 63] : '=';
    }
    out[o] = 0;
}

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
    w16(0); w16(0x8400); w16(0); w16(4); w16(0); w16(0); // cabecera: 4 respuestas

    rec_start("_airplay._tcp.local", 12, 1, &p);   // PTR
    wname(n_airplay);
    rec_end(p);

    rec_start(n_airplay, 33, 0x8001, &p);          // SRV
    w16(0); w16(0); w16(puerto);
    wname(host_local);
    rec_end(p);

    rec_start(n_airplay, 16, 0x8001, &p);          // TXT
    txt("deviceid=AA:BB:CC:DD:EE:01");
    txt("features=0x5A7FFFF7,0x1E");
    txt("model=AppleTV3,2");
    txt("srcvers=220.68");
    { char pkl[80]; strcpy(pkl, "pk="); a_hex(ed_pk, 32, pkl + 3); txt(pkl); }
    rec_end(p);

    rec_start(host_local, 1, 0x8001, &p);                // A (IP)
    w8(a); w8(b); w8(c); w8(d);
    rec_end(p);
}

// ---------- historial para poder tomar foto con calma ----------
static char historial[4][160];
static int total_hist = 0;
static int repetir = 0;   // cuantas veces mas se vuelve a mostrar el resumen

static void anotar(const char* linea) {
    strncpy(historial[total_hist % 4], linea, 159);
    historial[total_hist % 4][159] = 0;
    total_hist++;
    repetir = 5;
    FILE* f = fopen("/data/ronixz_cast.log", "a"); // por si quieres leerlo despues
    if (f) { fprintf(f, "%s\n", linea); fclose(f); }
}

static void mostrar_resumen(void) {
    char m[512];
    int pos = snprintf(m, sizeof(m), "Ronixz Cast - lo que ha pedido el iPhone (lo ultimo al final):");
    int desde = total_hist > 4 ? total_hist - 4 : 0;
    for (int i = desde; i < total_hist && pos < (int)sizeof(m) - 100; i++) {
        pos += snprintf(m + pos, sizeof(m) - pos, " [%d] %s", i + 1, historial[i % 4]);
    }
    aviso(m);
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

static void responder(int c, const char* buf, int n) {
    char cseq[16];
    sacar_cseq(buf, cseq, sizeof(cseq));
    if (strncmp(buf, "GET /info", 9) == 0) {
        char cuerpo[1400];
        char pkb64[64];
        a_b64(ed_pk, 32, pkb64);
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
            "<key>pk</key><data>%s</data>\n"
            "<key>vv</key><integer>2</integer>\n"
            "</dict></plist>\n", nombre, pkb64);
        enviar(c, "200 OK", cseq, "Content-Type: text/x-apple-plist+xml\r\n", cuerpo);
    } else if (strncmp(buf, "POST /pair-setup", 16) == 0) {
        // paso 2: la PS4 entrega su llave publica de identidad (32 bytes)
        enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", (const char*)ed_pk, 32);
    } else if (strncmp(buf, "POST /pair-verify", 17) == 0) {
        // paso 3: verificacion con cifrado de verdad
        const char* fin = strstr(buf, "\r\n\r\n");
        const unsigned char* body = fin ? (const unsigned char*)(fin + 4) : NULL;
        int body_len = body ? n - (int)((const char*)body - buf) : 0;
        if (body_len >= 68 && body[0] == 1) {
            const unsigned char* their_ecdh = body + 4;   // llave temporal del iPhone
            unsigned char ecdh_sk[32], ecdh_pk[32], shared[32];
            randombytes(ecdh_sk, 32);
            crypto_scalarmult_base(ecdh_pk, ecdh_sk);
            crypto_scalarmult(shared, ecdh_sk, their_ecdh);

            // firmar (llave temporal nuestra + llave temporal del iPhone)
            unsigned char msg[64], sm[128];
            unsigned long long smlen = 0;
            memcpy(msg, ecdh_pk, 32);
            memcpy(msg + 32, their_ecdh, 32);
            crypto_sign(sm, &smlen, msg, 64, ed_sk);   // sm = firma(64) + mensaje(64)

            // clave y vector de AES salen del secreto compartido
            unsigned char tmp[64], h[64], key[16], iv[16];
            memcpy(tmp, "Pair-Verify-AES-Key", 19);
            memcpy(tmp + 19, shared, 32);
            crypto_hash(h, tmp, 51);
            memcpy(key, h, 16);
            memcpy(tmp, "Pair-Verify-AES-IV", 18);
            memcpy(tmp + 18, shared, 32);
            crypto_hash(h, tmp, 50);
            memcpy(iv, h, 16);

            struct AES_ctx ctx;
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CTR_xcrypt_buffer(&ctx, sm, 64);   // cifrar la firma

            unsigned char resp[96];
            memcpy(resp, ecdh_pk, 32);
            memcpy(resp + 32, sm, 64);
            enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", (const char*)resp, 96);
        } else {
            // paso 4: confirmacion final del iPhone
            enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", NULL, 0);
        }
    } else if (strncmp(buf, "POST /fp-setup", 14) == 0) {
        // paso esperado 4: FairPlay de Apple (respuesta de relleno)
        char d[142];
        for (int i = 0; i < 142; i++) d[i] = (char)((i * 3 + 9) & 255);
        enviar_bin(c, "200 OK", cseq, "Content-Type: application/octet-stream\r\n", d, 142);
    } else if (strncmp(buf, "OPTIONS", 7) == 0) {
        enviar(c, "200 OK", cseq, "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET\r\n", NULL);
    } else {
        // SETUP, RECORD, /play, /stream, etc.: contestar OK y anotar que pidio
        enviar(c, "200 OK", cseq, "", NULL);
    }
}

// ---------- programa principal ----------
int main(void) {
    sceSysmoduleLoadModuleInternal(ORBIS_SYSMODULE_INTERNAL_NET);
    sceNetInit();
    sceNetPoolCreate("ronixz", 64 * 1024, 0);

    crypto_sign_keypair(ed_pk, ed_sk);

    // Detectar IP y nombre de la consola
    sceNetCtlInit();
    OrbisNetCtlInfo info;

    memset(&info, 0, sizeof(info));
    if (sceNetCtlGetInfo(ORBIS_NET_CTL_INFO_IP_ADDRESS, &info) == 0) {
        strncpy(ps4_ip, info.ip_address, sizeof(ps4_ip) - 1);
    } else {
        aviso("Ronixz Cast: no pude detectar la IP. Revisa el Wi-Fi/cable.");
        return 1;
    }

    memset(&info, 0, sizeof(info));
    if (sceNetCtlGetInfo(ORBIS_NET_CTL_INFO_DHCP_HOSTNAME, &info) == 0
        && info.dhcp_hostname[0] != 0) {
        strncpy(nombre, info.dhcp_hostname, sizeof(nombre) - 1);
        nombre[sizeof(nombre) - 1] = 0;
        for (char* q = nombre; *q; q++) if (*q == '.') *q = '-'; // los puntos romperian el nombre
    }

    // Armar el "host" a partir del nombre de la consola (minusculas, sin espacios ni simbolos)
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

    // Pedirle a la PS4 un puerto libre y dejarlo escuchando
    int ts = sceNetSocket("airplay", ORBIS_NET_AF_INET, ORBIS_NET_SOCK_STREAM, 0);
    if (ts >= 0) {
        MiSockaddrIn ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_len = sizeof(ta);
        ta.sin_family = ORBIS_NET_AF_INET;
        ta.sin_port = 0; // 0 = que la PS4 elija uno libre
        if (sceNetBind(ts, (OrbisNetSockaddr*)&ta, sizeof(ta)) == 0) {
            unsigned int tl = sizeof(ta);
            if (sceNetGetsockname(ts, (OrbisNetSockaddr*)&ta, &tl) == 0) {
                puerto = sceNetNtohs(ta.sin_port);
            }
            sceNetListen(ts, 5);
        }
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
        uint8_t* ab = (uint8_t*)&dest.sin_addr; // 224.0.0.251
        ab[0] = 224; ab[1] = 0; ab[2] = 0; ab[3] = 251;
    }

    armar();

    char msg[128];
    snprintf(msg, sizeof(msg), "Ronixz Cast listo. Nombre: %s, IP: %s, puerto: %d", nombre, ps4_ip, (int)puerto);
    aviso(msg);

    if (ts >= 0) {
        int uno2 = 1;
        sceNetSetsockopt(ts, ORBIS_NET_SOL_SOCKET, ORBIS_NET_SO_NBIO, &uno2, sizeof(uno2));
    }

    int vuelta = 0;
    int cli[4] = { -1, -1, -1, -1 };
    int ocio[4] = { 0, 0, 0, 0 };
    for (;;) {
        // anunciar la PS4 en la red cada ~2 segundos
        if (vuelta % 10 == 0) {
            sceNetSendto(s, pkt, plen, 0, (OrbisNetSockaddr*)&dest, sizeof(dest));
        }
        vuelta++;

        // volver a mostrar el resumen cada ~6 segundos (5 veces) para dar tiempo de tomar foto
        if (repetir > 0 && vuelta % 30 == 0) {
            mostrar_resumen();
            repetir--;
        }

        // atender al iPhone: aceptar conexiones y responder lo que pida
        if (ts >= 0) {
            MiSockaddrIn ca;
            unsigned int cl = sizeof(ca);
            memset(&ca, 0, sizeof(ca));
            int nuevo_c = sceNetAccept(ts, (OrbisNetSockaddr*)&ca, &cl);
            if (nuevo_c >= 0) {
                int uno3 = 1;
                sceNetSetsockopt(nuevo_c, ORBIS_NET_SOL_SOCKET, ORBIS_NET_SO_NBIO, &uno3, sizeof(uno3));
                int puesto = -1;
                for (int i = 0; i < 4; i++) if (cli[i] < 0) { puesto = i; break; }
                if (puesto < 0) { sceNetSocketClose(cli[0]); puesto = 0; }
                cli[puesto] = nuevo_c;
                ocio[puesto] = 0;
            }
            for (int i = 0; i < 4; i++) {
                if (cli[i] < 0) continue;
                char buf[4096];
                memset(buf, 0, sizeof(buf));
                int n = sceNetRecv(cli[i], buf, sizeof(buf) - 1, 0);
                if (n > 0) {
                    ocio[i] = 0;
                    // si el cuerpo llego cortado, esperar el resto (maximo ~0.5 s)
                    const char* fin_cab = strstr(buf, "\r\n\r\n");
                    const char* cl_ptr = strstr(buf, "Content-Length:");
                    if (fin_cab && cl_ptr) {
                        int cl_len = atoi(cl_ptr + 15);
                        int tiene = n - (int)((fin_cab + 4) - buf);
                        int intentos = 0;
                        while (tiene < cl_len && n < (int)sizeof(buf) - 1 && intentos < 100) {
                            int extra = sceNetRecv(cli[i], buf + n, sizeof(buf) - 1 - n, 0);
                            if (extra > 0) { n += extra; tiene += extra; }
                            else { sceKernelUsleep(5000); intentos++; }
                        }
                    }
                    char linea[90];
                    int k = 0;
                    for (int j = 0; j < n && k < 80 && buf[j] != '\r' && buf[j] != '\n'; j++) {
                        unsigned char ch = (unsigned char)buf[j];
                        linea[k++] = (ch >= 32 && ch < 127) ? (char)ch : '?';
                    }
                    linea[k] = 0;
                    const char* pcl = strstr(buf, "Content-Length:");
                    int cl_n = pcl ? atoi(pcl + 15) : 0;
                    char frag[60];
                    frag[0] = 0;
                    if (cl_n > 0 && strstr(linea, "pair") == NULL && strstr(linea, "fp-setup") == NULL) {
                        const char* fb = strstr(buf, "\r\n\r\n");
                        if (fb) {
                            fb += 4;
                            int jj = 0;
                            for (int q = 0; fb + q < buf + n && jj < 55; q++) {
                                unsigned char ch = (unsigned char)fb[q];
                                frag[jj++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
                            }
                            frag[jj] = 0;
                        }
                    }
                    char linea2[160];
                    snprintf(linea2, sizeof(linea2), "%s (cuerpo %d) %s", linea, cl_n, frag);
                    char m[300];
                    snprintf(m, sizeof(m), "Ronixz Cast: el iPhone pidio: %s", linea2);
                    aviso(m);
                    anotar(linea2);
                    responder(cli[i], buf, n);
                } else if (n == 0) {
                    sceNetSocketClose(cli[i]);
                    cli[i] = -1;
                } else {
                    ocio[i]++;
                    if (ocio[i] > 150) { // ~30 segundos sin nada
                        sceNetSocketClose(cli[i]);
                        cli[i] = -1;
                    }
                }
            }
        }
        sceKernelUsleep(200000);
    }
    return 0;
}
