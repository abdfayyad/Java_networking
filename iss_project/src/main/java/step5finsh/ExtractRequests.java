package step5finsh;

public class ExtractRequests {

    public static class RequestObject {
        private String id;
        private String request;

        public RequestObject(String id, String request) {
            this.id = id;
            this.request = request;
        }

        public String getId() {
            return id;
        }

        public String getRequest() {
            return request;
        }

        @Override
        public String toString() {
            return "ID: " + id + ", Request: " + request;
        }
    }

//    public static void main(String[] args) {
////        List<String> lines = readLinesFromFile("stored_requests.txt");
////        List<RequestObject> requestObjects = parseLines(lines);
////        List<String> requests = extractRequests(requestObjects);
////        openMyFile(requests);
//
//
//    }

//    private static void openMyFile(List<String> list) {
//        // Print the list of requests
//        for (String request : list) {
//            System.out.println(request);
//
//            File file = new File(request);
//
//            // Check if the file exists and can be opened
//            if (file.exists()) {
//                try {
//                    Desktop.getDesktop().open(file);  // Open the file
//                    System.out.println("File opened successfully!");
//                } catch (IOException e) {
//                    System.out.println("Failed to open the file.");
//                    e.printStackTrace();
//                }
//            } else {
//                System.out.println("File does not exist on the desktop.");
//            }
//        }
//    }
//
//    private static List<String> readLinesFromFile(String filePath) {
//        List<String> lines = new ArrayList<>();
//        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
//            String line;
//            while ((line = br.readLine()) != null) {
//                lines.add(line);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        return lines;
//    }
//
//    private static List<RequestObject> parseLines(List<String> lines) {
//        List<RequestObject> requestObjects = new ArrayList<>();
//        for (String line : lines) {
//            String[] parts = line.split(": ");
//
//            if (parts.length == 2 && parts[0].length() == 7) {
//                String id = parts[0];//.split(",")[0];
//                String request = parts[1];
//                requestObjects.add(new RequestObject(id, request));
//            }
//        }
//        return requestObjects;
//    }
//
//    private static List<String> extractRequests(List<RequestObject> requestObjects) {
//        List<String> requests = new ArrayList<>();
//        for (RequestObject obj : requestObjects) {
//            requests.add(obj.getRequest());
//        }
//        return requests;
//    }
}













