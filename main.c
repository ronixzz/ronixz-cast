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

#define NOMBRE_RESPALDO "Ronixz PS4"
static char host_local[64];      // se arma solo a partir del nombre de la consola
static uint16_t puerto = 7000;   // se reemplaza por un puerto libre que elige la PS4

static char ps4_ip[16]   = "0.0.0.0";
static char nombre[48]   = NOMBRE_RESPALDO;
static char n_airplay[96];   // "<nombre>._airplay._tcp.local"

// ---------- aviso en pantalla de la PS4 ----------
typedef struct {
    int type; int req_id; int priority; int msg_id; int target_id; int user_id;
    int unk1; int unk2; int app_id; int error_num; int unk3;
    char use_icon_image_uri; char message[1024]; char icon_uri[1024]; char unk[1024];
} NotifReq;
int sceKernelSendNotificationRequest(int, NotifReq*, size_t, int);

static void aviso(const char* texto) {
    NotifReq n;
    memset(&n, 0, sizeof(n));
    n.type = 0;
    n.use_icon_image_uri = 1;
    n.target_id = -1;
    strncpy(n.message, texto, sizeof(n.message) - 1);
    strcpy(n.icon_uri, "cxml://psnotification/tex_icon_system");
    sceKernelSendNotificationRequest(0, &n, sizeof(n), 0);
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
    rec_end(p);

    rec_start(host_local, 1, 0x8001, &p);                // A (IP)
    w8(a); w8(b); w8(c); w8(d);
    rec_end(p);
}

// ---------- programa principal ----------
int main(void) {
    sceSysmoduleLoadModuleInternal(ORBIS_SYSMODULE_INTERNAL_NET);
    sceNetInit();
    sceNetPoolCreate("ronixz", 64 * 1024, 0);

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
        OrbisNetSockaddrIn ta;
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

    OrbisNetSockaddrIn dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_len = sizeof(dest);
    dest.sin_family = ORBIS_NET_AF_INET;
    dest.sin_port = sceNetHtons(5353);
    sceNetInetPton(ORBIS_NET_AF_INET, "224.0.0.251", &dest.sin_addr);

    armar();

    char msg[128];
    snprintf(msg, sizeof(msg), "Ronixz Cast iniciado. Busca '%s' en AirPlay.", nombre);
    aviso(msg);

    for (;;) {
        sceNetSendto(s, pkt, plen, 0, (OrbisNetSockaddr*)&dest, sizeof(dest));
        sceKernelSleep(2);
    }
    return 0;
}
