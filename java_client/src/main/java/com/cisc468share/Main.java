package com.cisc468share;

import com.cisc468share.runtime.RuntimeLauncher;

public class Main {

    public static void main(String[] args) {

        try {

            RuntimeLauncher runtime = new RuntimeLauncher();

            runtime.run();

        } catch (Exception e) {

            e.printStackTrace();

        }

    }
}
