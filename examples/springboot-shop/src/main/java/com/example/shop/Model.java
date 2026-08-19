package com.example.shop;

import java.util.Map;

/** Request and response shapes for the shop API. */
public class Model {

    public record Card(String number, String cvv, String holder) {}

    public record Customer(String name, String email, String phone) {}

    public record OrderRequest(String sku, int qty, Customer customer, Card card) {}

    public record ChargeRequest(double amount, Card card, String orderRef) {}

    public record LoginRequest(String username, String password) {}

    public record Product(String sku, String name, double price, int stock) {}

    public static Map<String, Product> catalog() {
        return Map.of(
                "SKU-100", new Product("SKU-100", "Mechanical keyboard", 129.00, 42),
                "SKU-200", new Product("SKU-200", "27\" monitor", 349.00, 7),
                "SKU-300", new Product("SKU-300", "Desk lamp", 39.50, 0),
                "SKU-400", new Product("SKU-400", "USB-C dock", 189.00, 15));
    }
}
