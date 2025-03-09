#include <stdio.h>
#define TAX_RATE 0.10

struct Car{
    char model[50];
    float price;
};

struct Customer{
    char name[50];
    char paymentType[20];
};

float calculateTotalPrice(float price){
    return price + (price * TAX_RATE);
}
int main(){
    struct Car car;
    struct Customer customer;
    float totalPrice;

    printf("Enter Customer Name:  ");
    scanf("  %[^\n]s", customer.name);

    printf("Enter Car Model:  ");
    scanf("  %[^\n]s", car.model);
    
    printf("Enter Car Price:  ");
    scanf(" %f", &car.price);

    printf("Enter Payment Type (Cash/Loan/EMI):  ");
    scanf(" %[^\n]s", customer.paymentType);

    totalPrice = calculateTotalPrice(car.price);

    printf("\n===== Car Purchase Summary =====\n");
    printf("Customer Name: %s\n", customer.name);
    printf("Car Model : %s\n", car.model);
    printf("Base Price : $%.2f\n", car.price);
    printf("Tax (10%%) :  $%.2f\n", car.price * TAX_RATE);
    printf("Total Price :  $%.2f\n", totalPrice);
    printf("Payment Method : %s\n", customer.paymentType);
    printf("=========================\n");

    return 0;
}