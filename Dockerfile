# Use official PHP-Apache image
FROM php:8.2-apache

# Enable extensions you need (mysqli, pdo)
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copy project files into container
COPY . /var/www/html/

# Set permissions
RUN chmod -R 755 /var/www/html/
