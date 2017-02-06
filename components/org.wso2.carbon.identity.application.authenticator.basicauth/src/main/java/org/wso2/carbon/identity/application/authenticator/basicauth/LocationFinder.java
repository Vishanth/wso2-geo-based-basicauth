package org.wso2.carbon.identity.application.authenticator.basicauth;

import org.json.JSONObject;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

public class LocationFinder {

    public JSONObject getLocation (String ipAddress) {

        String apiUrl = "http://freegeoip.net/json/" + ipAddress;
        JSONObject location = null;

        try {
            InputStream is = new URL(apiUrl).openStream();

            BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
            String jsonText = readAll(rd);
            location = new JSONObject(jsonText);

            is.close();

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return location;
    }

    private static String readAll(Reader rd) throws IOException {
        StringBuilder sb = new StringBuilder();
        int cp;
        while ((cp = rd.read()) != -1) {
            sb.append((char) cp);
        }
        return sb.toString();
    }

    public String getCountryFromIpAddress(String ipAddress) {
        String country = null;

        try {
            JSONObject location = getLocation(ipAddress);
            country = location.getString("country_name");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return country;
    }
}