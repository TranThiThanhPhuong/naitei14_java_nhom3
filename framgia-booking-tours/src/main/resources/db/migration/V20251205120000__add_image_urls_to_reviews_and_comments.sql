-- Add image_urls column to reviews table
ALTER TABLE reviews ADD COLUMN image_urls TEXT NULL COMMENT 'JSON array of image URLs';

-- Add image_urls column to comments table  
ALTER TABLE comments ADD COLUMN image_urls TEXT NULL COMMENT 'JSON array of image URLs';
