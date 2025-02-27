namespace TransactionApi.Class
{
    public class SuccessResponse
    {

        public int result { get; set; }
        public long totalamount { get; set; }
        public long totaldiscount { get; set; }
        public long finalamount { get; set; }
        //public string resultmessage { get; set; }

    }

    public class FailedResponse
    {

        public int result { get; set; }
        public string resultmessage { get; set; }

    }

}
