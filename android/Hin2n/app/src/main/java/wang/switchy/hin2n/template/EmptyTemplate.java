package wang.switchy.hin2n.template;

import android.content.Context;
import android.view.View;

/**
 * Created by janiszhang on 2018/4/13.
 */

public class EmptyTemplate extends BaseTemplate {
    private View mContentView;

    public EmptyTemplate(Context context) {
        super(context);
    }

    @Override
    public void setContentView(View contentView) {
        this.mContentView = contentView;
    }

    @Override
    public View getPageView() {
        return mContentView;
    }
}
