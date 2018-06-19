package wang.switchy.hin2n;


import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.support.multidex.MultiDexApplication;

import wang.switchy.hin2n.storage.db.base.DaoMaster;
import wang.switchy.hin2n.storage.db.base.DaoSession;


/**
 * Created by janiszhang on 2018/4/19.
 */

public class Hin2nApplication extends MultiDexApplication {

    public Context AppContext;

    private DaoMaster.DevOpenHelper mHelper;
    private SQLiteDatabase db;
    private DaoMaster mDaoMaster;
    private DaoSession mDaoSession;

    public static Hin2nApplication instance;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;

        AppContext = this;

        setDatabase();
    }

    public static Hin2nApplication getInstance(){
        return instance;
    }

    private void setDatabase() {
        mHelper = new DaoMaster.DevOpenHelper(this, "N2N-db", null);
        db = mHelper.getWritableDatabase();
        mDaoMaster = new DaoMaster(db);
        mDaoSession = mDaoMaster.newSession();
    }

    public DaoSession getDaoSession() {
        return mDaoSession;
    }

    public SQLiteDatabase getDb() {
        return db;
    }
}

