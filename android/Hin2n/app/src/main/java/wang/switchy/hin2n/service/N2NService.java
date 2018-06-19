package wang.switchy.hin2n.service;

import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import org.greenrobot.eventbus.EventBus;

import java.io.IOException;
import java.net.InetAddress;

import wang.switchy.hin2n.event.ErrorEvent;
import wang.switchy.hin2n.event.StartEvent;
import wang.switchy.hin2n.event.StopEvent;
import wang.switchy.hin2n.model.EdgeCmd;
import wang.switchy.hin2n.model.EdgeStatus;
import wang.switchy.hin2n.model.N2NSettingInfo;

import static wang.switchy.hin2n.model.EdgeCmd.getRandomMac;

/**
 * Created by janiszhang on 2018/4/15.
 */

public class N2NService extends VpnService {

    public static N2NService INSTANCE;

    private ParcelFileDescriptor mParcelFileDescriptor = null;
    private EdgeCmd cmd;
    private boolean mStartResult;

    @Override
    public void onCreate() {
        super.onCreate();
        INSTANCE = this;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Bundle setting = intent.getBundleExtra("Setting");
        N2NSettingInfo n2nSettingInfo = setting.getParcelable("n2nSettingInfo");

        Builder b = new Builder();
        b.setMtu(n2nSettingInfo.getMtu());
        String ipAddress = n2nSettingInfo.getIp();
        b.addAddress(ipAddress, getIpAddrPrefixLength(n2nSettingInfo.getNetmask()));
        String route = getRoute(ipAddress, getIpAddrPrefixLength(n2nSettingInfo.getNetmask()));
        b.addRoute(route, getIpAddrPrefixLength(n2nSettingInfo.getNetmask()));

        try {
            mParcelFileDescriptor = b.setSession("N2N").establish();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            Toast.makeText(INSTANCE, "Parameter is not accepted by the operating system.", Toast.LENGTH_SHORT).show();
            return super.onStartCommand(intent, flags, startId);
        } catch (IllegalStateException e) {
            e.printStackTrace();
            Toast.makeText(INSTANCE, "Parameter cannot be applied by the operating system.", Toast.LENGTH_SHORT).show();
            return super.onStartCommand(intent, flags, startId);
        }

        if (mParcelFileDescriptor == null) {
            Toast.makeText(INSTANCE, "~error~", Toast.LENGTH_SHORT).show();
            return super.onStartCommand(intent, flags, startId);
        }

        cmd = new EdgeCmd();
        cmd.ipAddr = n2nSettingInfo.getIp();
        cmd.ipNetmask = n2nSettingInfo.getNetmask();
        cmd.supernodes = new String[2];
        cmd.supernodes[0] = n2nSettingInfo.getSuperNode();
        cmd.supernodes[1] = n2nSettingInfo.getSuperNodeBackup();
        cmd.community = n2nSettingInfo.getCommunity();
        cmd.encKey = n2nSettingInfo.getPassword();
        cmd.encKeyFile = null;
        cmd.macAddr = n2nSettingInfo.getMacAddr();
        cmd.mtu = n2nSettingInfo.getMtu();
        cmd.reResoveSupernodeIP = n2nSettingInfo.isResoveSupernodeIP();
        cmd.localPort = n2nSettingInfo.getLocalPort();
        cmd.allowRouting = n2nSettingInfo.isAllowRouting();
        cmd.dropMuticast = n2nSettingInfo.isDropMuticast();
        cmd.traceLevel = n2nSettingInfo.getTraceLevel();
        cmd.vpnFd = mParcelFileDescriptor.detachFd();

        try {
            mStartResult = startEdge(cmd);
            if (!mStartResult) {
                EventBus.getDefault().post(new ErrorEvent());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return super.onStartCommand(intent, flags, startId);
    }

    public void stop() {
        stopEdge();

        try {
            if (mParcelFileDescriptor != null) {
                mParcelFileDescriptor.close();
                mParcelFileDescriptor = null;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        EventBus.getDefault().post(new StopEvent());
    }

    @Override
    public void onRevoke() {
        super.onRevoke();
        stop();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    public native boolean startEdge(EdgeCmd cmd);

    public native void stopEdge();

    public native EdgeStatus getEdgeStatus();

    public void reportEdgeStatus(EdgeStatus status) {
        if (status != null) {
            if (status.isRunning) {
                EventBus.getDefault().post(new StartEvent());
            } else {
                EventBus.getDefault().post(new StopEvent());

            }
        }
    }

    private int getIpAddrPrefixLength(String netmask) {
        try {
            byte[] byteAddr = InetAddress.getByName(netmask).getAddress();
            int prefixLength = 0;
            for (int i = 0; i < byteAddr.length; i++) {
                for (int j = 0; j < 8; j++) {
                    if ((byteAddr[i] << j & 0xFF) != 0) {
                        prefixLength++;
                    } else {
                        return prefixLength;
                    }
                }
            }
            return prefixLength;
        } catch (Exception e) {
            return -1;
        }
    }

    private String getRoute(String ipAddr, int prefixLength) {
        byte[] arr = {(byte) 0x00, (byte) 0x80, (byte) 0xC0, (byte) 0xE0, (byte) 0xF0, (byte) 0xF8, (byte) 0xFC, (byte) 0xFE, (byte) 0xFF};

        if (prefixLength > 32 || prefixLength < 0) {
            return "";
        }
        try {
            byte[] byteAddr = InetAddress.getByName(ipAddr).getAddress();
            int idx = 0;
            while (prefixLength >= 8) {
                idx++;
                prefixLength -= 8;
            }
            if (idx < byteAddr.length) {
                byteAddr[idx++] &= arr[prefixLength];
            }
            for (; idx < byteAddr.length; idx++) {
                byteAddr[idx] = (byte) 0x00;
            }
            return InetAddress.getByAddress(byteAddr).getHostAddress();
        } catch (Exception e) {
            return "";
        }
    }
}
