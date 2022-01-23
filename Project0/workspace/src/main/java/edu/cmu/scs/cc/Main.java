package edu.cmu.scs.cc;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.Map.Entry;

public class Main {

    /**
     * Main entry.
     *
     * <p>The main method reads from {@link System#in}
     * and writes to `output`.
     *
     * <p>I/O must be encoding-aware instead of relying on the system default
     * encoding. {@link java.io.OutputStreamWriter(OutputStream)} and
     * {@link java.io.InputStreamReader(InputStream)} below are encoding-naive.
     * You need to replace them with their encoding-aware constructor
     * counterparts.
     *
     * @param args command-line args
     * @throws IOException if IO error occurs.
     */
    public static void main(final String[] args) throws IOException {
        // TODO: modify and make the try-with-resources statement encoding aware
        try (PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream("output")), true);
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(System.in))) {
            // do not change the code below
            TreeMap<String, Integer> pageviewMap = new TreeMap<>();
            String page;
            while ((page = br.readLine()) != null) {
                String[] columns = DataFilter.getColumns(page);
                if (DataFilter.checkAllRules(columns)) {
                    try {
                        pageviewMap.put(columns[DataFilter.TITLE],
                                pageviewMap.getOrDefault(columns[DataFilter.TITLE], 0)
                                        + Integer.parseInt(columns[DataFilter.ACCESS]));
                    } catch (NumberFormatException e) {
                        //ignore it
                    }
                }
            }
            LinkedList<Entry<String, Integer>> linkedList = DataFilter.sortRecords(pageviewMap);
            for (Entry<String, Integer> entry : linkedList) {
                printWriter.print(entry.getKey() + "\t" + entry.getValue() + "\n");
            }
        }
    }
}