package wang.switchy.hin2n.storage.db.base.model;

import org.greenrobot.greendao.annotation.Entity;
import org.greenrobot.greendao.annotation.Generated;
import org.greenrobot.greendao.annotation.Id;

/**
 * Created by janiszhang on 2018/5/4.
 */

@Entity(
        nameInDb = "N2NSettingList"
)
public class N2NSettingModel /*implements Parcelable*/ {

    @Id(autoincrement = true)
    Long id;
    String name;
    String ip;
    String netmask;
    String community;
    String password;
    String superNode;
    boolean moreSettings;
    String superNodeBackup;
    String macAddr;
    int mtu;
    boolean resoveSupernodeIP;
    int localPort;
    boolean allowRouting;
    boolean dropMuticast;
    int traceLevel;
    boolean isSelcected;

    @Generated(hash = 1390425120)
    public N2NSettingModel(Long id, String name, String ip, String netmask,
            String community, String password, String superNode,
            boolean moreSettings, String superNodeBackup, String macAddr, int mtu,
            boolean resoveSupernodeIP, int localPort, boolean allowRouting,
            boolean dropMuticast, int traceLevel, boolean isSelcected) {
        this.id = id;
        this.name = name;
        this.ip = ip;
        this.netmask = netmask;
        this.community = community;
        this.password = password;
        this.superNode = superNode;
        this.moreSettings = moreSettings;
        this.superNodeBackup = superNodeBackup;
        this.macAddr = macAddr;
        this.mtu = mtu;
        this.resoveSupernodeIP = resoveSupernodeIP;
        this.localPort = localPort;
        this.allowRouting = allowRouting;
        this.dropMuticast = dropMuticast;
        this.traceLevel = traceLevel;
        this.isSelcected = isSelcected;
    }

    @Generated(hash = 998225630)
    public N2NSettingModel() {
    }

    public String getSuperNode() {
        return this.superNode;
    }

    public void setSuperNode(String superNode) {
        this.superNode = superNode;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCommunity() {
        return this.community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public String getNetmask() {
        return this.netmask;
    }

    public void setNetmask(String netmask) {
        this.netmask = netmask;
    }

    public String getIp() {
        return this.ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public Long getId() {
        return this.id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean getIsSelcected() {
        return this.isSelcected;
    }

    public void setIsSelcected(boolean isSelcected) {
        this.isSelcected = isSelcected;
    }

    public int getTraceLevel() {
        return this.traceLevel;
    }

    public void setTraceLevel(int traceLevel) {
        this.traceLevel = traceLevel;
    }

    public boolean getDropMuticast() {
        return this.dropMuticast;
    }

    public void setDropMuticast(boolean dropMuticast) {
        this.dropMuticast = dropMuticast;
    }

    public boolean getAllowRouting() {
        return this.allowRouting;
    }

    public void setAllowRouting(boolean allowRouting) {
        this.allowRouting = allowRouting;
    }

    public int getLocalPort() {
        return this.localPort;
    }

    public void setLocalPort(int localPort) {
        this.localPort = localPort;
    }

    public boolean getResoveSupernodeIP() {
        return this.resoveSupernodeIP;
    }

    public void setResoveSupernodeIP(boolean resoveSupernodeIP) {
        this.resoveSupernodeIP = resoveSupernodeIP;
    }

    public int getMtu() {
        return this.mtu;
    }

    public void setMtu(int mtu) {
        this.mtu = mtu;
    }

    public String getMacAddr() {
        return this.macAddr;
    }

    public void setMacAddr(String macAddr) {
        this.macAddr = macAddr;
    }

    public String getSuperNodeBackup() {
        return this.superNodeBackup;
    }

    public void setSuperNodeBackup(String superNodeBackup) {
        this.superNodeBackup = superNodeBackup;
    }

    public boolean getMoreSettings() {
        return this.moreSettings;
    }

    public void setMoreSettings(boolean moreSettings) {
        this.moreSettings = moreSettings;
    }

    @Override
    public String toString() {
        return "N2NSettingModel{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", ip='" + ip + '\'' +
                ", netmask='" + netmask + '\'' +
                ", community='" + community + '\'' +
                ", password='" + password + '\'' +
                ", superNode='" + superNode + '\'' +
                ", moreSettings=" + moreSettings +
                ", superNodeBackup='" + superNodeBackup + '\'' +
                ", macAddr='" + macAddr + '\'' +
                ", mtu=" + mtu +
                ", resoveSupernodeIP=" + resoveSupernodeIP +
                ", localPort=" + localPort +
                ", allowRouting=" + allowRouting +
                ", dropMuticast=" + dropMuticast +
                ", traceLevel=" + traceLevel +
                ", isSelcected=" + isSelcected +
                '}';
    }
}
