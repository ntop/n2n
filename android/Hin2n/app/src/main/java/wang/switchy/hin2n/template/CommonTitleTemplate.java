package wang.switchy.hin2n.template;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;

import wang.switchy.hin2n.R;

/**
 * Created by janiszhang on 2018/4/13.
 */

public class CommonTitleTemplate extends BaseTemplate {
    private Context mContext;

    private LinearLayout mPageView;

    private RelativeLayout mTitleLayout;

    private FrameLayout mContainerLayout;

    public final ImageView mLeftImg;
    public final ImageView mRightImg;


    public CommonTitleTemplate(Context context, String title) {
        super(context);

        this.mContext = context;

        mPageView = (LinearLayout) LayoutInflater.from(mContext).inflate(R.layout.main_template_view, null);

        mTitleLayout = (RelativeLayout) mPageView.findViewById(R.id.rl_title);
        mContainerLayout = (FrameLayout) mPageView.findViewById(R.id.fl_container);

        TextView titleText = (TextView) mPageView.findViewById(R.id.tv_title);

        mLeftImg = (ImageView) mPageView.findViewById(R.id.iv_left_img);
        mRightImg = (ImageView) mPageView.findViewById(R.id.iv_right_img);

        titleText.setText(title);

    }

    @Override
    public void setContentView(View contentView) {
        RelativeLayout.LayoutParams contentViewLayoutParams = new RelativeLayout.LayoutParams(RelativeLayout.LayoutParams.MATCH_PARENT, RelativeLayout.LayoutParams.MATCH_PARENT);
        mContainerLayout.addView(contentView, contentViewLayoutParams);
    }

    @Override
    public View getPageView() {
        return mPageView;
    }
}
