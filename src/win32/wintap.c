/*
  (C) 2007-22 - Luca Deri <deri@ntop.org>
*/

#include "defs.h"
#ifndef _WIN64
#include <iphlpapi.h>
#endif

#include "n2n.h"
#include "n2n_win32.h"

/* ***************************************************** */

void initWin32() {
  WSADATA wsaData;
  int err;

  err = WSAStartup(MAKEWORD(2, 2), &wsaData );
  if( err != 0 ) {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    printf("FATAL ERROR: unable to initialise Winsock 2.x.");
    exit(EXIT_FAILURE);
  }
}


void destroyWin32() {
	WSACleanup();
}

struct win_adapter_info {
  HANDLE handle;
  char adapterid[1024];
  char adaptername[1024];
};

/* ***************************************************** */

static HANDLE open_tap_device(const char *adapterid) {
  char tapname[1024];
  _snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);

  return(CreateFile(tapname, GENERIC_WRITE | GENERIC_READ,
               0, /* Don't let other processes share or open
               the resource until the handle's been closed */
               0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0));
}

/* ***************************************************** */

static void iterate_win_network_adapters(
    int (*callback)(struct win_adapter_info*, struct tuntap_dev *),
    void *userdata) {
  HKEY key, key2;
  char regpath[1024];
  int rc;
  int err, i;
  struct win_adapter_info adapter;

  /* Open registry and look for network adapters */
  if((rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key))) {
    printf("Unable to read registry: [rc=%d]\n", rc);
    exit(EXIT_FAILURE);
    /* MSVC Note: If you keep getting rc=2 errors, make sure you set:
       Project -> Properties -> Configuration Properties -> General -> Character set
       to: "Use Multi-Byte Character Set"
    */
  }

  for (i = 0; ; i++) {
    long unsigned int len = sizeof(adapter.adapterid);
    if(RegEnumKeyEx(key, i, (LPTSTR)adapter.adapterid, &len, 0, 0, 0, NULL))
      break;

    /* Find out more about this adapter */

    _snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, adapter.adapterid);
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)regpath, 0, KEY_READ, &key2))
      continue;

    len = sizeof(adapter.adaptername);
    err = RegQueryValueEx(key2, "Name", 0, 0, (unsigned char *)adapter.adaptername, &len);

    RegCloseKey(key2);

    if(err)
      continue;

    
    adapter.handle = open_tap_device(adapter.adapterid);

    if(adapter.handle != INVALID_HANDLE_VALUE) {
      /* Valid device, use the callback */
      if(!callback(&adapter, userdata))
        break;
      else
        CloseHandle(adapter.handle);
      /* continue */
    }
  }

  RegCloseKey(key);
}

/* ***************************************************** */

static int print_adapter_callback(struct win_adapter_info *adapter, struct tuntap_dev *device) {
  printf(" %s - %s\n", adapter->adapterid, adapter->adaptername);

  /* continue */
  return(1);
}

void win_print_available_adapters() {
  iterate_win_network_adapters(print_adapter_callback, NULL);
}

/* ***************************************************** */

static int lookup_adapter_info_reg(const char *target_adapter, char *regpath, size_t regpath_size) {
  HKEY key, key2;
  int rc;
  char index[16];
  int err, i;
  devstr_t adapter_name;
  int rv = 0;

  if((rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_INFO_KEY, 0, KEY_READ, &key))) {
    printf("Unable to read registry: %s, [rc=%d]\n", ADAPTER_INFO_KEY, rc);
    exit(EXIT_FAILURE);
  }

  for(i = 0; ; i++) {
    long unsigned int len = sizeof(index);
    if(RegEnumKeyEx(key, i, (LPTSTR)index, &len, 0, 0, 0, NULL))
      break;

    _snprintf(regpath, regpath_size, "%s\\%s", ADAPTER_INFO_KEY, index);
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)regpath, 0, KEY_READ, &key2))
      continue;

    len = sizeof(adapter_name);
    err = RegQueryValueEx(key2, "NetCfgInstanceId", 0, 0, (unsigned char *)adapter_name, &len);

    RegCloseKey(key2);

    if(err)
      continue;

    if(!strcmp(adapter_name, target_adapter)) {
      rv = 1;
      break;
    }
  }

  RegCloseKey(key);
  return(rv);
}

/* ***************************************************** */

static void set_interface_mac(struct tuntap_dev *device, const char *mac_str) {
  char cmd[256];
  char mac_buf[18];
  char adapter_info_reg[1024];

  if(strlen(mac_str) != 17) {
    printf("Invalid MAC: %s\n", mac_str);
    exit(EXIT_FAILURE);
  }

  /* Remove the colons */
  for(int i=0; i<6; i++) {
    mac_buf[i*2] = mac_str[2*i + i];
    mac_buf[i*2+1] = mac_str[2*i + i + 1];
  }
  mac_buf[12] = '\0';

  if(!lookup_adapter_info_reg(device->device_name, adapter_info_reg, sizeof(adapter_info_reg))) {
    printf("Could not determine adapter MAC registry key\n");
    exit(EXIT_FAILURE);
  }

  _snprintf(cmd, sizeof(cmd),
      "reg add HKEY_LOCAL_MACHINE\\%s /v MAC /d %s /f > nul", adapter_info_reg, mac_buf);
  system(cmd);

  /* Put down then up again to apply */
  CloseHandle(device->device_handle);
  _snprintf(cmd, sizeof(cmd), "netsh interface set interface \"%s\" disabled > nul", device->ifName);
  system(cmd);
  _snprintf(cmd, sizeof(cmd), "netsh interface set interface \"%s\" enabled > nul", device->ifName);
  system(cmd);

  device->device_handle = open_tap_device(device->device_name);
  if(device->device_handle == INVALID_HANDLE_VALUE) {
    printf("Reopening TAP device \"%s\" failed\n", device->device_name);
    exit(EXIT_FAILURE);
  }
}

/* ***************************************************** */

static int choose_adapter_callback(struct win_adapter_info *adapter, struct tuntap_dev *device) {
  if(device->device_name) {
    /* A device name filter was set, name must match */
    if(strcmp(device->device_name, adapter->adapterid) &&
       strcmp(device->device_name, adapter->adaptername)) {
      /* Not found, continue */
      return(1);
    }
  } /* otherwise just pick the first available adapter */

  /* Adapter found, break */
  device->device_handle = adapter->handle;
  if(device->device_name) free(device->device_name);
  device->device_name = _strdup(adapter->adapterid);
  device->ifName = _strdup(adapter->adaptername);
  return(0);
}

/* ***************************************************** */

int open_wintap(struct tuntap_dev *device,
                const char * devname,
                const char * address_mode, /* "static" or "dhcp" */
                char *device_ip, 
                char *device_mask,
                const char *device_mac, 
                int mtu,
                int metric) {

  char cmd[256];
  DWORD len;
  ULONG status = TRUE;

  memset(device, 0, sizeof(struct tuntap_dev));
  device->device_handle = INVALID_HANDLE_VALUE;
  device->device_name = devname[0] ? _strdup(devname) : NULL;
  device->ifName = NULL;
  device->ip_addr = inet_addr(device_ip);

  iterate_win_network_adapters(choose_adapter_callback, device);

  if(device->device_handle == INVALID_HANDLE_VALUE) {
    if(!devname[0])
      printf("No Windows tap devices found, did you run tapinstall.exe?\n");
    else
      printf("Cannot find tap device \"%s\"\n", devname);
    return -1;
  }

  /* ************************************** */

  /* interface index, required for routing */

  ULONG buffer_len = 0;
  IP_ADAPTER_INFO *buffer;

  // get required buffer size and allocate buffer
  GetAdaptersInfo(NULL, &buffer_len);
  buffer = malloc(buffer_len);

  // find device by name and get its index
  if(buffer && !GetAdaptersInfo(buffer, &buffer_len)) {
    IP_ADAPTER_INFO *i;
    for(i = buffer; i != NULL; i = i->Next) {
      if(!strcmp(device->device_name, i->AdapterName)) {
        device->if_idx = i->Index;
        break;
      }
    }
  }

  free(buffer);

  /* ************************************** */

  if(device_mac && device_mac[0])
    set_interface_mac(device, device_mac);

    /* Get MAC address from tap device->device_name */

  if(!DeviceIoControl(device->device_handle, TAP_IOCTL_GET_MAC,
                      device->mac_addr, sizeof(device->mac_addr),
                      device->mac_addr, sizeof(device->mac_addr), &len, 0)) {
    printf("Could not get MAC address from Windows tap %s (%s)\n",
           device->device_name, device->ifName);
    return -1;
  }

   device->mtu = mtu;

   printf("Open device [name=%s][ip=%s][ifName=%s][MTU=%d][mac=%02X:%02X:%02X:%02X:%02X:%02X]\n",
	 device->device_name, device_ip, device->ifName, device->mtu,
	 device->mac_addr[0] & 0xFF,
	 device->mac_addr[1] & 0xFF,
	 device->mac_addr[2] & 0xFF,
	 device->mac_addr[3] & 0xFF,
	 device->mac_addr[4] & 0xFF,
	 device->mac_addr[5] & 0xFF);

  /* ****************** */

  if ( 0 == strcmp("dhcp", address_mode) )
  {
      _snprintf(cmd, sizeof(cmd),
                "netsh interface ip set address \"%s\" dhcp > nul",
                device->ifName);
  }
  else
  {
      _snprintf(cmd, sizeof(cmd),
                "netsh interface ip set address \"%s\" static %s %s > nul",
                device->ifName, device_ip, device_mask);
  }

  if(system(cmd) == 0) {
    device->ip_addr = inet_addr(device_ip);
    device->device_mask = inet_addr(device_mask);
  } else
    printf("WARNING: Unable to set device %s IP address [%s]\n",
			device->ifName, cmd);

  /* ****************** */

  /* MTU */

  _snprintf(cmd, sizeof(cmd),
    "netsh interface ipv4 set subinterface \"%s\" mtu=%d store=persistent > nul",
    device->ifName, mtu);

  if(system(cmd) != 0)
    printf("WARNING: Unable to set device %s parameters MTU=%d store=persistent [%s]\n",
      device->ifName, mtu, cmd);

  /* ****************** */

#ifdef _WIN64
  /* Setting the metric is not actually 64-bit specific.
   * The assumption here is that anyone needing a metric set will also
   * need a new enough OS that they will be on 64-bit.
   *
   * The alternative is that people trying to run old games are probably on
   * Windows XP and are probably 32-bit.
   */

  /* metric */

  PMIB_IPINTERFACE_ROW Row;

  if(metric) { /* try to change only if a value has been given, otherwise leave with default or as set before */
    // find & store original metric
    Row = calloc(1, sizeof(MIB_IPINTERFACE_ROW));
    InitializeIpInterfaceEntry(Row);
    Row->InterfaceIndex = device->if_idx;
    Row->Family = AF_INET;
    GetIpInterfaceEntry(Row);

    device->metric_original = Row->Metric;
    device->metric = metric;

    // set new value
    Row->Metric = metric;

    // store
    Row->SitePrefixLength = 0; /* if not set to zero, following function call fails... */
    SetIpInterfaceEntry(Row);
    
    free(Row);
  }
#endif /* _WIN64 */

  /* ****************** */


  /* set driver media status to 'connected' (i.e. set the interface up) */
  if (!DeviceIoControl (device->device_handle, TAP_IOCTL_SET_MEDIA_STATUS,
			&status, sizeof (status),
			&status, sizeof (status), &len, NULL))
    printf("WARNING: Unable to enable TAP adapter\n");

  /*
   * Initialize overlapped structures
   */
  device->overlap_read.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  device->overlap_write.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!device->overlap_read.hEvent || !device->overlap_write.hEvent) {
    return -1;
  }

  return(0);
}

/* ************************************************ */

int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len)
{
  DWORD read_size;
  int last_err;

  ResetEvent(tuntap->overlap_read.hEvent);
  if (ReadFile(tuntap->device_handle, buf, len, &read_size, &tuntap->overlap_read)) {
    //printf("tun_read(len=%d)\n", read_size);
    return read_size;
  }
  switch (last_err = GetLastError()) {
  case ERROR_IO_PENDING:
    WaitForSingleObject(tuntap->overlap_read.hEvent, INFINITE);
    GetOverlappedResult(tuntap->device_handle, &tuntap->overlap_read, &read_size, FALSE);
    return read_size;
    break;
  default:
    printf("GetLastError() returned %d\n", last_err);
    break;
  }

  return -1;
}
/* ************************************************ */

int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len)
{
  DWORD write_size;

  //printf("tun_write(len=%d)\n", len);

  ResetEvent(tuntap->overlap_write.hEvent);
  if (WriteFile(tuntap->device_handle,
		buf,
		len,
		&write_size,
		&tuntap->overlap_write)) {
    //printf("DONE tun_write(len=%d)\n", write_size);
    return write_size;
  }
  switch (GetLastError()) {
  case ERROR_IO_PENDING:
    WaitForSingleObject(tuntap->overlap_write.hEvent, INFINITE);
    GetOverlappedResult(tuntap->device_handle, &tuntap->overlap_write,
			&write_size, FALSE);
    return write_size;
    break;
  default:
    break;
  }

  return -1;
}

/* ************************************************ */

int tuntap_open(struct tuntap_dev *device, 
                char *dev, 
                const char *address_mode, /* static or dhcp */
                char *device_ip, 
                char *device_mask, 
                const char * device_mac, 
                int mtu,
                int metric) {
    return(open_wintap(device, dev, address_mode, device_ip, device_mask, device_mac, mtu, metric));
}

/* ************************************************ */

void tuntap_close(struct tuntap_dev *tuntap) {

#ifdef _WIN64
  /* See comment in open_wintap for notes about this ifdef */
  PMIB_IPINTERFACE_ROW Row;

  if(tuntap->metric) { /* only required if a value has been given (and thus stored) */
    // find device entry
    Row = calloc(1, sizeof(MIB_IPINTERFACE_ROW));
    InitializeIpInterfaceEntry(Row);
    Row->InterfaceIndex = tuntap->if_idx;
    Row->Family = AF_INET;
    GetIpInterfaceEntry(Row);

    // restore original value
    Row->Metric = tuntap->metric_original;

    // store
    Row->SitePrefixLength = 0; /* if not set to zero, following function call fails... */
    SetIpInterfaceEntry(Row);

    free(Row);
  }
#endif /* _WIN64 */

  CloseHandle(tuntap->device_handle);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap)
{
}

/* ************************************************ */

#if 0
int main(int argc, char* argv[]) {
  struct tuntap_dev tuntap;
  int i;
  int mtu = 1400;

  printf("Welcome to n2n\n");
  initWin32();
  open_wintap(&tuntap, "static", "1.2.3.20", "255.255.255.0", mtu, 0);

  for(i=0; i<10; i++) {
    u_char buf[MTU];
    int rc;

    rc = tun_read(&tuntap, buf, sizeof(buf));
    buf[0]=2;
    buf[1]=3;
    buf[2]=4;

    printf("tun_read returned %d\n", rc);
    rc = tun_write(&tuntap, buf, rc);
    printf("tun_write returned %d\n", rc);
  }
  // rc = tun_open (device->device_name, IF_MODE_TUN);
  WSACleanup ();
  return(0);
}

#endif
