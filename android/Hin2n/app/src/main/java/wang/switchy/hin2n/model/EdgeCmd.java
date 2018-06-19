package wang.switchy.hin2n.model;

import android.util.Log;

import java.util.Random;
import java.util.Vector;

public class EdgeCmd {
    public String ipAddr;
    public String ipNetmask;
    public String[] supernodes;
    public String community;
    public String encKey;
    public String encKeyFile;
    public String macAddr;
    public int mtu;
    public boolean reResoveSupernodeIP;
    public int localPort;
    public boolean allowRouting;
    public boolean dropMuticast;
    public int traceLevel;
    public int vpnFd;

    public static boolean checkIPV4(String ip) {
        if (ip == null || ip.length() < 7 || ip.length() > 15) {
            return false;
        }
        String[] split = ip.split("\\.");
        if (split == null || split.length != 4) {
            return false;
        }
        try {
            for (int i = 0; i < split.length; ++i) {
                int n = Integer.parseInt(split[i]);
                if (n < 0 || n > 255 || !String.valueOf(n).equals(split[i])) {
                    return false;
                }
            }
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public static boolean checkIPV4Mask(String netmask) {
        int[] arr = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF};

        if (netmask == null || netmask.length() < 7 || netmask.length() > 15) {
            return false;
        }
        String[] split = netmask.split("\\.");
        if (split == null || split.length != 4) {
            return false;
        }
        try {
            for (int i = 0; i < split.length; ++i) {
                int n = Integer.parseInt(split[i]);
                boolean flag = false;
                for (int j = 0; j < arr.length; ++j) {
                    if (n == arr[j]) {
                        flag = true;
                        break;
                    }
                }
                if (!flag || !String.valueOf(n).equals(split[i])) {
                    return false;
                }
            }
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public static boolean checkSupernode(String supernode) {
        if (supernode == null || supernode.isEmpty() || supernode.length() > 47) {
            return false;
        }
        String[] split = supernode.split(":");
        if (split == null || split.length != 2 || split[0].isEmpty()) {
            return false;
        }
        int n = Integer.parseInt(split[1]);
        if (n < 0 || n > 65535 || !String.valueOf(n).equals(split[1])) {
            return false;
        }

        return true;
    }

    public static boolean checkCommunity(String community) {
        if (community == null || community.isEmpty() || community.length() > 15) {
            return false;
        }

        return true;
    }

    public static boolean checkEncKey(String encKey) {
        return true;
    }

    public static boolean checkEncKeyFile(String encKeyFile) {
        return true;
    }

    public static boolean checkMacAddr(String mac) {
        String hex = "0123456789abcdef";
        if (mac == null || mac.length() != 17) {
            return false;
        }
        for (int i = 0; i < mac.length(); ++i) {
            char c = mac.charAt(i);
            if ((i + 1) % 3 == 0) {
                if (c != ':') {
                    return false;
                }
                continue;
            }
            if (!hex.contains(String.valueOf(c))) {
                return false;
            }
        }

        return true;
    }

    public static boolean checkInt(int n, int min, int max) {
        if (n < min || n > max) {
            return false;
        }

        return true;
    }

    public static String getRandomMac() {
        String mac = "", hex="0123456789abcdef";
        Random rand = new Random();
        for (int i = 0; i < 17; ++i)
        {
            if ((i + 1) % 3 == 0) {
                mac += ':';
                continue;
            }
            mac += hex.charAt(rand.nextInt(16));
        }
        return mac;
    }
}

