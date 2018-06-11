package wang.switchy.hin2n.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import org.w3c.dom.Text;

import java.util.List;

import wang.switchy.hin2n.R;
import wang.switchy.hin2n.entity.SettingItemEntity;

/**
 * Created by janiszhang on 2018/5/6.
 */

public class SettingItemAdapter extends BaseAdapter {

    private Context mContext;
    private List<SettingItemEntity> mSettingItemEntities;
    private final LayoutInflater mLayoutInflater;

    public SettingItemAdapter(Context context, List<SettingItemEntity> settingItemEntities) {
        mContext = context;
        mSettingItemEntities = settingItemEntities;

        mLayoutInflater = LayoutInflater.from(mContext);
    }

    @Override
    public int getCount() {
        return mSettingItemEntities.size();
    }

    @Override
    public Object getItem(int i) {
        return mSettingItemEntities.get(i);
    }

    @Override
    public long getItemId(int i) {
        return i;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder;
        final SettingItemEntity settingItemEntity = mSettingItemEntities.get(position);
        if (convertView == null) {
            convertView = mLayoutInflater.inflate(R.layout.layout_setting_item, null);
            viewHolder = new ViewHolder();
            viewHolder.settingName = (TextView) convertView.findViewById(R.id.tv_setting_name);
            viewHolder.imgIsSelected = (ImageView) convertView.findViewById(R.id.iv_selected);
            viewHolder.moreInfo = (TextView) convertView.findViewById(R.id.tv_more);

            convertView.setTag(viewHolder);

        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }

        viewHolder.settingName.setText(settingItemEntity.getSettingName());
        if (settingItemEntity.isSelected()) {
            viewHolder.imgIsSelected.setVisibility(View.VISIBLE);
        } else {
            viewHolder.imgIsSelected.setVisibility(View.INVISIBLE);

        }

        viewHolder.moreInfo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                settingItemEntity.mOnMoreBtnClickListener.onClick();
            }
        });
        return convertView;
    }

    class ViewHolder {
        TextView settingName;
        ImageView imgIsSelected;
        TextView moreInfo;
    }
}
