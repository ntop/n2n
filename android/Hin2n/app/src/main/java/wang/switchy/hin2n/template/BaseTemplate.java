package wang.switchy.hin2n.template;

import android.content.Context;
import android.view.View;

/**
 * Created by janiszhang on 2018/4/13.
 */

public abstract class BaseTemplate {
    protected Context mContext;

    public BaseTemplate(Context context) {
        this.mContext = context;
    }

    public abstract void setContentView(View contentView);

    public abstract View getPageView();

}
