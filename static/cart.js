document.addEventListener('DOMContentLoaded', () => {
    // Динамическое обновление корзины
    const cartButtons = document.querySelectorAll('.add-to-cart');
    cartButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            e.preventDefault();
            fetch('/cart', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `product_id=${e.target.dataset.productId}`
            }).then(response => location.reload());
        });
    });
});
