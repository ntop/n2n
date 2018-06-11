package wang.switchy.hin2n.activity;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.support.design.widget.TextInputLayout;
import android.text.TextUtils;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.Toast;

import java.util.ArrayList;

import wang.switchy.hin2n.Hin2nApplication;
import wang.switchy.hin2n.service.N2NService;
import wang.switchy.hin2n.R;
import wang.switchy.hin2n.model.EdgeCmd;
import wang.switchy.hin2n.model.N2NSettingInfo;
import wang.switchy.hin2n.storage.db.base.N2NSettingModelDao;
import wang.switchy.hin2n.storage.db.base.model.N2NSettingModel;
import wang.switchy.hin2n.template.BaseTemplate;
import wang.switchy.hin2n.template.CommonTitleTemplate;

/**
 * Created by janiszhang on 2018/5/4.
 */

public class SettingDetailsActivity extends BaseActivity implements View.OnClickListener {

    public static int TYPE_SETTING_ADD = 0;
    public static int TYPE_SETTING_MODIFY = 1;
    private int type = TYPE_SETTING_ADD;

    private TextInputLayout mIpAddressTIL;
    private TextInputLayout mNetMaskTIL;
    private TextInputLayout mCommunityTIL;
    private TextInputLayout mEncryptTIL;
    private TextInputLayout mSuperNodeTIL;
    private Button mSaveBtn;
    private SharedPreferences mHin2nSp;
    private SharedPreferences.Editor mHin2nEdit;
    private TextInputLayout mSettingName;
    private CheckBox mSaveAndSetCheckBox;

    private TextInputLayout mSuperNodeBackup;
    private TextInputLayout mMacAddr;
    private TextInputLayout mMtu;
    private CheckBox mResoveSupernodeIPCheckBox;
    private TextInputLayout mLocalPort;
    private CheckBox mAllowRoutinCheckBox;
    private CheckBox mDropMuticastCheckBox;
    private Spinner mTraceLevelSpinner;
    private CheckBox mMoreSettingCheckBox;
    private RelativeLayout mMoreSettingView;
    private N2NSettingModel mN2NSettingModel;
    private Button mModifyBtn;
    private LinearLayout mButtons;
    private Button mDeleteBtn;
    private long mSaveId;
    private ArrayList<String> mTraceLevelList;


    @Override
    protected BaseTemplate createTemplate() {
        CommonTitleTemplate titleTemplate = new CommonTitleTemplate(mContext, "Add New Setting");
        titleTemplate.mLeftImg.setVisibility(View.VISIBLE);
        titleTemplate.mLeftImg.setImageResource(R.drawable.titlebar_icon_return_selector);
        titleTemplate.mLeftImg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                finish();
            }
        });
        return titleTemplate;
    }

    @Override
    protected void doOnCreate(Bundle savedInstanceState) {

        mHin2nSp = getSharedPreferences("Hin2n", MODE_PRIVATE);
        mHin2nEdit = mHin2nSp.edit();

        mSettingName = (TextInputLayout) findViewById(R.id.til_setting_name);
        mIpAddressTIL = (TextInputLayout) findViewById(R.id.til_ip_address);
        mNetMaskTIL = (TextInputLayout) findViewById(R.id.til_net_mask);
        mCommunityTIL = (TextInputLayout) findViewById(R.id.til_community);
        mEncryptTIL = (TextInputLayout) findViewById(R.id.til_encrypt);
        mEncryptTIL.getEditText().setTransformationMethod(PasswordTransformationMethod.getInstance());//隐藏
        mSuperNodeTIL = (TextInputLayout) findViewById(R.id.til_super_node);
        mMoreSettingView = (RelativeLayout) findViewById(R.id.rl_more_setting);
        mMoreSettingCheckBox = (CheckBox) findViewById(R.id.more_setting_check_box);
        mMoreSettingCheckBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                if (b) {
                    mMoreSettingView.setVisibility(View.VISIBLE);
                } else {
                    mMoreSettingView.setVisibility(View.GONE);
                }
            }
        });

        mSuperNodeBackup = (TextInputLayout) findViewById(R.id.til_super_node_2);
        mMacAddr = (TextInputLayout) findViewById(R.id.til_mac_addr);
        mMtu = (TextInputLayout) findViewById(R.id.til_mtu);
        mResoveSupernodeIPCheckBox = (CheckBox) findViewById(R.id.resove_super_node_ip_check_box);
        mLocalPort = (TextInputLayout) findViewById(R.id.til_local_port);
        mAllowRoutinCheckBox = (CheckBox) findViewById(R.id.allow_routing_check_box);
        mDropMuticastCheckBox = (CheckBox) findViewById(R.id.drop_muticast_check_box);
        mTraceLevelSpinner = (Spinner) findViewById(R.id.spinner_trace_level);
        mTraceLevelList = new ArrayList<>();
        // 0：ERROR, 1: WARNING, 2: NORMAL, 3: INFO, 4: DEBUG
        mTraceLevelList.add("ERROR");
        mTraceLevelList.add("WARNING");
        mTraceLevelList.add("NORMAL");
        mTraceLevelList.add("INFO");
        mTraceLevelList.add("DEBUG");

        final ArrayAdapter<String> traceLevelAdapter = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, mTraceLevelList);
        traceLevelAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

        mTraceLevelSpinner.setAdapter(traceLevelAdapter);

        mTraceLevelSpinner.setSelection(1);

        mTraceLevelSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                String item = traceLevelAdapter.getItem(position);
                int selectedItemPosition = mTraceLevelSpinner.getSelectedItemPosition();
                String traceLevel = mTraceLevelList.get(selectedItemPosition);
            }

            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });

        mSaveAndSetCheckBox = (CheckBox) findViewById(R.id.check_box);
        mSaveBtn = (Button) findViewById(R.id.btn_save);
        mSaveBtn.setOnClickListener(this);
        mButtons = (LinearLayout) findViewById(R.id.ll_buttons);
        mModifyBtn = (Button) findViewById(R.id.btn_modify);
        mModifyBtn.setOnClickListener(this);
        mDeleteBtn = (Button) findViewById(R.id.btn_delete);
        mDeleteBtn.setOnClickListener(this);

        Intent intent = getIntent();
        type = intent.getIntExtra("type", 0);

        if (type == TYPE_SETTING_ADD) {
            mMtu.getEditText().setText("1400");
            mDropMuticastCheckBox.setChecked(true);
            mTraceLevelSpinner.setSelection(1);
            mSaveBtn.setVisibility(View.VISIBLE);
            mButtons.setVisibility(View.GONE);
        } else if (type == TYPE_SETTING_MODIFY) {
            mSaveId = intent.getLongExtra("saveId", 0);
            mN2NSettingModel = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().load(mSaveId);
            mSettingName.getEditText().setText(mN2NSettingModel.getName());
            mIpAddressTIL.getEditText().setText(mN2NSettingModel.getIp());
            mNetMaskTIL.getEditText().setText(mN2NSettingModel.getNetmask());
            mCommunityTIL.getEditText().setText(mN2NSettingModel.getCommunity());
            mEncryptTIL.getEditText().setText(mN2NSettingModel.getPassword());
            mSuperNodeTIL.getEditText().setText(mN2NSettingModel.getSuperNode());
            mSuperNodeBackup.getEditText().setText(mN2NSettingModel.getSuperNodeBackup());
            mMacAddr.getEditText().setText(mN2NSettingModel.getMacAddr());
            mMtu.getEditText().setText(String.valueOf(mN2NSettingModel.getMtu()));
            mResoveSupernodeIPCheckBox.setChecked(mN2NSettingModel.getResoveSupernodeIP());
            mLocalPort.getEditText().setText(String.valueOf(mN2NSettingModel.getLocalPort()));
            mAllowRoutinCheckBox.setChecked(mN2NSettingModel.getAllowRouting());
            mDropMuticastCheckBox.setChecked(mN2NSettingModel.getDropMuticast());
            mTraceLevelSpinner.setSelection(Integer.valueOf(mN2NSettingModel.getTraceLevel()));
            if (mN2NSettingModel.getMoreSettings()) {
                mMoreSettingCheckBox.setChecked(true);
                mMoreSettingView.setVisibility(View.VISIBLE);
            } else {
                mMoreSettingCheckBox.setChecked(false);
            }
            mButtons.setVisibility(View.VISIBLE);
            mSaveBtn.setVisibility(View.GONE);
        }
    }

    @Override
    protected int getContentLayout() {
        return R.layout.activity_add_item;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100 && resultCode == -RESULT_OK) {
            Intent intent = new Intent(SettingDetailsActivity.this, N2NService.class);
            Bundle bundle = new Bundle();
            N2NSettingInfo n2NSettingInfo = new N2NSettingInfo(mN2NSettingModel);
            bundle.putParcelable("n2nSettingInfo", n2NSettingInfo);
            intent.putExtra("Setting", bundle);
            startService(intent);
        }
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_save:
                if (!checkValues()) {
                    return;
                }

                if (mSaveAndSetCheckBox.isChecked()) {
                    Long currentSettingId = mHin2nSp.getLong("current_setting_id", -1);
                    if (currentSettingId != -1) {
                        N2NSettingModel currentSettingItem = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().load((long) currentSettingId);
                        if (currentSettingItem != null) {
                            currentSettingItem.setIsSelcected(false);
                            Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().update(currentSettingItem);
                        }
                    }

                    N2NSettingModelDao n2NSettingModelDao = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
                    String settingName = mSettingName.getEditText().getText().toString();
                    String setingNameTmp = settingName;
                    int i = 0;
                    while (n2NSettingModelDao.queryBuilder().where(N2NSettingModelDao.Properties.Name.eq(settingName)).unique() != null) {
                        i++;
                        settingName = setingNameTmp + "(" + i + ")";

                    }
                    long id;
                    if (mMoreSettingCheckBox.isChecked()) {
                        mN2NSettingModel = new N2NSettingModel(null, settingName, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), true, mSuperNodeBackup.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMacAddr.getEditText().getText().toString()) ? EdgeCmd.getRandomMac() : mMacAddr.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMtu.getEditText().getText().toString()) ? 1400 : Integer.valueOf(mMtu.getEditText().getText().toString()),
                                mResoveSupernodeIPCheckBox.isChecked(), TextUtils.isEmpty(mLocalPort.getEditText().getText().toString()) ? 0 : Integer.valueOf(mLocalPort.getEditText().getText().toString()),
                                mAllowRoutinCheckBox.isChecked(), mDropMuticastCheckBox.isChecked(), mTraceLevelSpinner.getSelectedItemPosition(), true);
                        id = n2NSettingModelDao.insert(mN2NSettingModel);
                    } else {
                        mN2NSettingModel = new N2NSettingModel(null, settingName, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), false, "", EdgeCmd.getRandomMac(), 1400, false, 0, false, true, 1, true);
                        id = n2NSettingModelDao.insert(mN2NSettingModel);
                    }

                    mHin2nEdit.putLong("current_setting_id", id);
                    mHin2nEdit.commit();

                    if (N2NService.INSTANCE != null && N2NService.INSTANCE.getEdgeStatus().isRunning) {
                        N2NService.INSTANCE.stop();
                    }

                    Intent vpnPrepareIntent = VpnService.prepare(SettingDetailsActivity.this);
                    if (vpnPrepareIntent != null) {
                        startActivityForResult(vpnPrepareIntent, 100);
                    } else {
                        onActivityResult(100, RESULT_OK, null);
                    }
                } else {
                    N2NSettingModelDao n2NSettingModelDao = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
                    String settingName = mSettingName.getEditText().getText().toString();
                    String setingNameTmp = settingName;
                    int i = 0;
                    while (n2NSettingModelDao.queryBuilder().where(N2NSettingModelDao.Properties.Name.eq(settingName)).unique() != null) {
                        i++;
                        settingName = setingNameTmp + "(" + i + ")";

                    }
                    Long id;
                    if (mMoreSettingCheckBox.isChecked()) {
                        mN2NSettingModel = new N2NSettingModel(null, settingName, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), true, mSuperNodeBackup.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMacAddr.getEditText().getText().toString()) ? EdgeCmd.getRandomMac() : mMacAddr.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMtu.getEditText().getText().toString()) ? 1400 : Integer.valueOf(mMtu.getEditText().getText().toString()),
                                mResoveSupernodeIPCheckBox.isChecked(), TextUtils.isEmpty(mLocalPort.getEditText().getText().toString()) ? 0 : Integer.valueOf(mLocalPort.getEditText().getText().toString()),
                                mAllowRoutinCheckBox.isChecked(), mDropMuticastCheckBox.isChecked(), mTraceLevelSpinner.getSelectedItemPosition(), false);
                        id = n2NSettingModelDao.insert(mN2NSettingModel);
                    } else {
                        mN2NSettingModel = new N2NSettingModel(null, settingName, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), false, "", EdgeCmd.getRandomMac(), 1400, false, 0, false, true, 1, false);

                        id = n2NSettingModelDao.insert(mN2NSettingModel);
                    }
                }

                Toast.makeText(mContext, "Add Succeed", Toast.LENGTH_SHORT).show();
                finish();
                break;

            case R.id.btn_modify:
                if (!checkValues()) {
                    return;
                }

                if (mSaveAndSetCheckBox.isChecked()) {
                    Long currentSettingId = mHin2nSp.getLong("current_setting_id", -1);

                    if (currentSettingId != -1) {
                        N2NSettingModel currentSettingItem = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().load((long) currentSettingId);
                        if (currentSettingItem != null) {
                            currentSettingItem.setIsSelcected(false);
                            Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().update(currentSettingItem);
                        }
                    }

                    N2NSettingModelDao n2NSettingModelDao1 = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
                    String settingName1 = mSettingName.getEditText().getText().toString();
                    String setingNameTmp1 = settingName1;
                    int i1 = 0;
                    N2NSettingModel n2NSettingModelTmp = n2NSettingModelDao1.queryBuilder().where(N2NSettingModelDao.Properties.Name.eq(settingName1)).unique();

                    while (n2NSettingModelTmp != null) {
                        if (n2NSettingModelTmp.getId() == mSaveId) {
                            break;
                        }

                        i1++;
                        settingName1 = setingNameTmp1 + "(" + i1 + ")";

                        n2NSettingModelTmp = n2NSettingModelDao1.queryBuilder().where(N2NSettingModelDao.Properties.Name.eq(settingName1)).unique();
                    }

                    long id;
                    if (mMoreSettingCheckBox.isChecked()) {
                        mN2NSettingModel = new N2NSettingModel(mSaveId, settingName1, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), true, mSuperNodeBackup.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMacAddr.getEditText().getText().toString()) ? EdgeCmd.getRandomMac() : mMacAddr.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMtu.getEditText().getText().toString()) ? 1400 : Integer.valueOf(mMtu.getEditText().getText().toString()),
                                mResoveSupernodeIPCheckBox.isChecked(), TextUtils.isEmpty(mLocalPort.getEditText().getText().toString()) ? 0 : Integer.valueOf(mLocalPort.getEditText().getText().toString()),
                                mAllowRoutinCheckBox.isChecked(), mDropMuticastCheckBox.isChecked(), mTraceLevelSpinner.getSelectedItemPosition(), true);
                        n2NSettingModelDao1.update(mN2NSettingModel);
                    } else {
                        mN2NSettingModel = new N2NSettingModel(mSaveId, settingName1, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), false, "", EdgeCmd.getRandomMac(), 1400, false, 0, false, true, 1, true);
                        n2NSettingModelDao1.update(mN2NSettingModel);
                    }

                    mHin2nEdit.putLong("current_setting_id", mSaveId);
                    mHin2nEdit.commit();

                    if (N2NService.INSTANCE != null && N2NService.INSTANCE.getEdgeStatus().isRunning) {
                        N2NService.INSTANCE.stop();
                    }

                    Intent vpnPrepareIntent = VpnService.prepare(SettingDetailsActivity.this);
                    if (vpnPrepareIntent != null) {
                        startActivityForResult(vpnPrepareIntent, 100);
                    } else {
                        onActivityResult(100, RESULT_OK, null);
                    }
                } else {
                    N2NSettingModelDao n2NSettingModelDao1 = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
                    String settingName1 = mSettingName.getEditText().getText().toString();
                    String setingNameTmp1 = settingName1;
                    int i1 = 0;
                    N2NSettingModel n2NSettingModelTmp = n2NSettingModelDao1.queryBuilder().where(N2NSettingModelDao.Properties.Name.eq(settingName1)).unique();

                    while (n2NSettingModelTmp != null) {
                        if (n2NSettingModelTmp.getId() == mSaveId) {
                            break;
                        }

                        i1++;
                        settingName1 = setingNameTmp1 + "(" + i1 + ")";

                        n2NSettingModelTmp = n2NSettingModelDao1.queryBuilder().where(N2NSettingModelDao.Properties.Name.eq(settingName1)).unique();
                    }
                    Long id;
                    if (mMoreSettingCheckBox.isChecked()) {
                        mN2NSettingModel = new N2NSettingModel(mSaveId, settingName1, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), true, mSuperNodeBackup.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMacAddr.getEditText().getText().toString()) ? EdgeCmd.getRandomMac() : mMacAddr.getEditText().getText().toString(),
                                TextUtils.isEmpty(mMtu.getEditText().getText().toString()) ? 1400 : Integer.valueOf(mMtu.getEditText().getText().toString()),
                                mResoveSupernodeIPCheckBox.isChecked(), TextUtils.isEmpty(mLocalPort.getEditText().getText().toString()) ? 0 : Integer.valueOf(mLocalPort.getEditText().getText().toString()),
                                mAllowRoutinCheckBox.isChecked(), mDropMuticastCheckBox.isChecked(), mTraceLevelSpinner.getSelectedItemPosition(), mN2NSettingModel.getIsSelcected());
                        n2NSettingModelDao1.update(mN2NSettingModel);
                    } else {
                        mN2NSettingModel = new N2NSettingModel(mSaveId, settingName1, mIpAddressTIL.getEditText().getText().toString(),
                                TextUtils.isEmpty(mNetMaskTIL.getEditText().getText()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString(),
                                mCommunityTIL.getEditText().getText().toString(), mEncryptTIL.getEditText().getText().toString(),
                                mSuperNodeTIL.getEditText().getText().toString(), false, "", EdgeCmd.getRandomMac(), 1400, false, 0, false, true, 1, mN2NSettingModel.getIsSelcected());
                        n2NSettingModelDao1.update(mN2NSettingModel);
                    }
                }

                Toast.makeText(mContext, "Update Succeed", Toast.LENGTH_SHORT).show();

                finish();

                break;

            case R.id.btn_delete:
                N2NSettingModelDao n2NSettingModelDao = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
                n2NSettingModelDao.deleteByKey(mSaveId);

                Toast.makeText(mContext, "Delete Succeed", Toast.LENGTH_SHORT).show();

                finish();

                break;
            default:

                break;
        }
    }

    private boolean checkValues() {
        if (TextUtils.isEmpty(mSettingName.getEditText().getText())
                || TextUtils.isEmpty(mIpAddressTIL.getEditText().getText())
                || TextUtils.isEmpty(mCommunityTIL.getEditText().getText())
                || TextUtils.isEmpty(mSuperNodeTIL.getEditText().getText())) {
            if (TextUtils.isEmpty(mSuperNodeTIL.getEditText().getText())) {
                mSuperNodeTIL.setError("Required");
                mSuperNodeTIL.getEditText().requestFocus();
            } else {
                mSuperNodeTIL.setErrorEnabled(false);
            }

            if (TextUtils.isEmpty(mCommunityTIL.getEditText().getText())) {
                mCommunityTIL.setError("Required");
                mCommunityTIL.getEditText().requestFocus();
            } else {
                mCommunityTIL.setErrorEnabled(false);
            }

            if (TextUtils.isEmpty(mIpAddressTIL.getEditText().getText())) {
                mIpAddressTIL.setError("Required");
                mIpAddressTIL.getEditText().requestFocus();
            } else {
                mIpAddressTIL.setErrorEnabled(false);
            }

            if (TextUtils.isEmpty(mSettingName.getEditText().getText())) {
                mSettingName.setError("Required");
                mSettingName.getEditText().requestFocus();
            } else {
                mSettingName.setErrorEnabled(false);
            }

            return false;
        }

        if (!EdgeCmd.checkIPV4(mIpAddressTIL.getEditText().getText().toString())) {
            mIpAddressTIL.setError("IP Address Error!");
            mIpAddressTIL.getEditText().requestFocus();
            return false;
        } else {
            mIpAddressTIL.setErrorEnabled(false);
        }

        if (!EdgeCmd.checkIPV4Mask(TextUtils.isEmpty(mNetMaskTIL.getEditText().getText().toString()) ? "255.255.255.0" : mNetMaskTIL.getEditText().getText().toString())) {
            mNetMaskTIL.setError("NetMask Error!");
            mNetMaskTIL.getEditText().requestFocus();
            return false;
        } else {
            mNetMaskTIL.setErrorEnabled(false);
        }

        if (!EdgeCmd.checkCommunity(mCommunityTIL.getEditText().getText().toString())) {
            mCommunityTIL.setError("Community Error!");
            mCommunityTIL.getEditText().requestFocus();
            return false;
        } else {
            mCommunityTIL.setErrorEnabled(false);
        }

        if (!EdgeCmd.checkEncKey(mEncryptTIL.getEditText().getText().toString())) {
            mEncryptTIL.setError("Password Error!");
            mEncryptTIL.getEditText().requestFocus();
            return false;
        } else {
            mEncryptTIL.setErrorEnabled(false);
        }

        if (!EdgeCmd.checkSupernode(mSuperNodeTIL.getEditText().getText().toString())) {
            mSuperNodeTIL.setError("Supernode Error!");
            mSuperNodeTIL.getEditText().requestFocus();
            return false;

        } else {
            mSuperNodeTIL.setErrorEnabled(false);

        }

        if (mMoreSettingCheckBox.isChecked()) {
            if (!TextUtils.isEmpty(mSuperNodeBackup.getEditText().getText().toString()) && !EdgeCmd.checkSupernode(mSuperNodeBackup.getEditText().getText().toString())) {
                mSuperNodeBackup.setError("Supernode Back Error!");
                mSuperNodeBackup.getEditText().requestFocus();
                return false;
            } else {
                mSuperNodeBackup.setErrorEnabled(false);
            }

            if (!TextUtils.isEmpty(mMacAddr.getEditText().getText().toString()) && !EdgeCmd.checkMacAddr(mMacAddr.getEditText().getText().toString())) {
                mMacAddr.setError("Mac Address Error!");
                mMacAddr.getEditText().requestFocus();
                return false;
            } else {
                mMacAddr.setErrorEnabled(false);
            }

            if (!TextUtils.isEmpty(mMtu.getEditText().getText().toString()) && !EdgeCmd.checkInt(Integer.valueOf(mMtu.getEditText().getText().toString()), 46, 1500)) {
                mMtu.setError("Mtu Error!");
                mMtu.getEditText().requestFocus();
                return false;
            } else {
                mMtu.setErrorEnabled(false);
            }

            if (!TextUtils.isEmpty(mLocalPort.getEditText().getText().toString()) && !EdgeCmd.checkInt(Integer.valueOf(mLocalPort.getEditText().getText().toString()), 0, 65535)) {
                mLocalPort.setError("Local Port Error!");
                mLocalPort.getEditText().requestFocus();
                return false;
            } else {
                mLocalPort.setErrorEnabled(false);
            }
        }

        return true;
    }
}
