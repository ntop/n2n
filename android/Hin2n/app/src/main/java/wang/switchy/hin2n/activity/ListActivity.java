package wang.switchy.hin2n.activity;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import wang.switchy.hin2n.Hin2nApplication;
import wang.switchy.hin2n.service.N2NService;
import wang.switchy.hin2n.R;
import wang.switchy.hin2n.adapter.SettingItemAdapter;
import wang.switchy.hin2n.entity.SettingItemEntity;
import wang.switchy.hin2n.model.N2NSettingInfo;
import wang.switchy.hin2n.storage.db.base.N2NSettingModelDao;
import wang.switchy.hin2n.storage.db.base.model.N2NSettingModel;
import wang.switchy.hin2n.template.BaseTemplate;
import wang.switchy.hin2n.template.CommonTitleTemplate;


/**
 * Created by janiszhang on 2018/5/4.
 */

public class ListActivity extends BaseActivity {

    private ListView mSettingsListView;
    private SettingItemAdapter mSettingItemAdapter;
    private ArrayList<SettingItemEntity> mSettingItemEntities;

    private SharedPreferences mHin2nSp;
    private SharedPreferences.Editor mHin2nEdit;
    private TextView mMoreInfo;
    private N2NSettingModel mN2NSettingModel;

    @Override
    protected BaseTemplate createTemplate() {
        CommonTitleTemplate titleTemplate = new CommonTitleTemplate(mContext, "Setting List");
        titleTemplate.mRightImg.setVisibility(View.VISIBLE);
        titleTemplate.mRightImg.setImageResource(R.mipmap.img_add);
        titleTemplate.mRightImg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(ListActivity.this, SettingDetailsActivity.class);
                intent.putExtra("type", SettingDetailsActivity.TYPE_SETTING_ADD);
                startActivity(intent);
            }
        });

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

        mSettingsListView = (ListView) findViewById(R.id.lv_setting_item);

        mSettingItemEntities = new ArrayList<>();

        mSettingItemAdapter = new SettingItemAdapter(this, mSettingItemEntities);

        mSettingsListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long l) {

                Long currentSettingId = mHin2nSp.getLong("current_setting_id", -1);

                if (currentSettingId != -1) {
                    N2NSettingModel currentSettingItem = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().load((long) currentSettingId);
                    if (currentSettingItem != null) {
                        currentSettingItem.setIsSelcected(false);
                        Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao().update(currentSettingItem);
                    }
                }

                for (int i = 0; i < mSettingItemEntities.size(); i++) {
                    mSettingItemEntities.get(i).setSelected(false);
                }

                mSettingItemAdapter.notifyDataSetChanged();


                N2NSettingModelDao n2NSettingModelDao = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
                mN2NSettingModel = n2NSettingModelDao.load(mSettingItemEntities.get(position).getSaveId());
                mN2NSettingModel.setIsSelcected(true);

                n2NSettingModelDao.update(mN2NSettingModel);

                mHin2nEdit.putLong("current_setting_id", mN2NSettingModel.getId());
                mHin2nEdit.commit();
                mSettingItemEntities.get(position).setSelected(true);
                mSettingItemAdapter.notifyDataSetChanged();
            }
        });

        mSettingsListView.setAdapter(mSettingItemAdapter);
    }

    @Override
    protected void onResume() {
        super.onResume();

        N2NSettingModelDao n2NSettingModelDao = Hin2nApplication.getInstance().getDaoSession().getN2NSettingModelDao();
        List<N2NSettingModel> n2NSettingModels = n2NSettingModelDao.loadAll();

        N2NSettingModel n2NSettingModel;
        mSettingItemEntities.clear();
        for (int i = 0; i < n2NSettingModels.size(); i++) {
            n2NSettingModel = n2NSettingModels.get(i);
            final SettingItemEntity settingItemEntity = new SettingItemEntity(n2NSettingModel.getName(),
                    n2NSettingModel.getId(), n2NSettingModel.getIsSelcected());

            settingItemEntity.setOnMoreBtnClickListener(new SettingItemEntity.OnMoreBtnClickListener() {
                @Override
                public void onClick() {
                    Intent intent = new Intent(ListActivity.this, SettingDetailsActivity.class);
                    intent.putExtra("type", SettingDetailsActivity.TYPE_SETTING_MODIFY);
                    intent.putExtra("saveId", settingItemEntity.getSaveId());

                    startActivity(intent);
                }
            });
            mSettingItemEntities.add(settingItemEntity);
        }

        mSettingItemAdapter.notifyDataSetChanged();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100 && resultCode == RESULT_OK) {

            Intent intent = new Intent(ListActivity.this, N2NService.class);
            Bundle bundle = new Bundle();
            N2NSettingInfo n2NSettingInfo = new N2NSettingInfo(mN2NSettingModel);

            bundle.putParcelable("n2nSettingInfo", n2NSettingInfo);
            intent.putExtra("Setting", bundle);

            startService(intent);
        }
    }

    @Override
    protected int getContentLayout() {
        return R.layout.activity_setting_list;
    }
}
