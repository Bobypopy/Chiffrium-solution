package shop;

public class Checkout {
    private static final byte[] FIXED_IV = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    public void pay() throws Exception {
        Payments payments = new Payments();
        payments.seal(FIXED_IV, 1000);
    }
}
