package wang.switchy.hin2n.activity;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.greenrobot.eventbus.EventBus;
import org.greenrobot.eventbus.Subscribe;
import org.greenrobot.eventbus.ThreadMode;

import wang.switchy.hin2n.Hin2nApplication;
import wang.switchy.hin2n.service.N2NService;
import wang.switchy.hin2n.R;
import wang.switchy.hin2n.event.ErrorEvent;
import wang.switchy.hin2n.event.StartEvent;
import wang.switchy.hin2n.event.StopEvent;
import wang.switchy.hin2n.model.N2NSettingInfo;
import wang.switchy.hin2n.storage.db.base.model.N2NSettingModel;
import wang.switchy.hin2n.template.BaseTemplate;
import wang.switchy.hin2n.template.CommonTitleTemplate;


public class MainActivity extends BaseActivity {

    private Button mActionBtn;

    static {
        System.loadLibrary("uip");
        System.loadLibrary("n2n");
        System.loadLibrary("edge");

    }

    private N2NSettingModel mCurrentSettingInfo;
    private RelativeLayout mCurrentSettingItem;
    private TextView mCurrentSettingName;

    @Override
    protected BaseTemplate createTemplate() {
        CommonTitleTemplate titleTemplate = new CommonTitleTemplate(this, "Hin2n");
        titleTemplate.mRightImg.setImageResource(R.mipmap.img_add);
        titleTemplate.mRightImg.setVisibility(View.VISIBLE);
        titleTemplate.mRightImg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(MainActivity.this, SettingDetailsActivity.class);
                intent.putExtra("type", SettingDetailsActivity.TYPE_SETTING_ADD);
                startActivity(intent);
            }
        });

        return titleTemplate;
    }

    @Override
    protected void doOnCreate(Bundle savedInstanceState) {
        if (!EventBus.getDefault().isRegistered(this)) {
            EventBus.getDefault().register(this);
        }

        mCurrentSettingItem = (RelativeLayout) findViewById(R.id.rl_current_setting_item);
        mCurrentSettingItem.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (N2NService.INSTANCE != null && N2NService.INSTANCE.getEdgeStatus().isRunning) {
                    Toast.makeText(mContext, "~Running~", Toast.LENGTH_SHORT).show();

                } else {
                    startActivity(new Intent(MainActivity.this, ListActivity.class));

                }
            }
        });

        mCurrentSettingName = (TextView) findViewById(R.id.tv_current_setting_name);

        mActionBtn = (Button) findViewById(R.id.btn_action);

        if (N2NService.INSTANCE == null) {
            mActionBtn.setText("start");

        } else {
            if (N2NService.INSTANCE.getEdgeStatus().isRunning) {
                mActionBtn.setText("stop");
            } else {
                mActionBtn.setText("start");
            }
        }

        mActionBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (mCurrentSettingName.getText().equals("--null--")) {
                    Toast.makeText(mContext, "null setting", Toast.LENGTH_SHORT).show();
                    return;
                }

                if (N2NService.INSTANCE != null && N2NService.INSTANCE.getEdgeStatus().isRunning) {
                    N2NService.INSTANCE.stop();
                } else {
                    Intent vpnPrepareIntent = VpnService.prepare(MainActivity.this);

                    if (vpnPrepareIntent != null) {
                        startActivityForResult(vpnPrepareIntent, 100);
                    } else {
                        onActivityResult(100, RESULT_OK, null);
                    }
                }
            }
        });
    }

    @Override
    protected int getContentLayout() {
        return R.layout.activity_main;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100 && resultCode == RESULT_OK) {
            Intent intent = new Intent(MainActivity.this, N2NService.class);
            Bundle bundle = new Bundle();
            N2NSettingInfo n2NSettingInfo = new N2NSettingInfo(mCurrentSettingInfo);
            bundle.putParcelable("n2nSettingInfo", n2NSettingInfo);
            intent.putExtra("Setting", bundle);
            startService(intent);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        SharedPreferences n2nSp = getSharedPreferences("Hin2n", MODE_PRIVATE);
        Long currentSettingId = n2nSp.getLong("current_setting_id", -1);

        if (currentSettingId != -1) {
            mCurrentSettingInfo = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().load((long) currentSettingId);
            if (mCurrentSettingInfo != null) {
                mCurrentSettingName.setText(mCurrentSettingInfo.getName());
            } else {
                mCurrentSettingName.setText("--null--");

            }
        }
    }

    @Override
    protected void onPause() {
        super.onPause();

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (EventBus.getDefault().isRegistered(this)) {
            EventBus.getDefault().unregister(this);
        }
    }


    @Subscribe(threadMode = ThreadMode.MAIN)
    public void onStartEvent(StartEvent event) {
        mActionBtn.setText("stop");
    }

    @Subscribe(threadMode = ThreadMode.MAIN)
    public void onStopEvent(StopEvent event) {
        mActionBtn.setText("start");
    }

    @Subscribe(threadMode = ThreadMode.MAIN)
    public void onErrorEvent(ErrorEvent event) {
        mActionBtn.setText("start");
        Toast.makeText(mContext, "~_~Error~_~", Toast.LENGTH_SHORT).show();
    }
}
