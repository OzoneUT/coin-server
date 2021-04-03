package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v7"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func setupMongoDB() *mongo.Database {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url, found := os.LookupEnv("MONGODB_URL")
	if !found {
		log.Fatal("MONGODB_URL env variable not found!")
	}
	c, err := mongo.Connect(ctx, options.Client().ApplyURI(url))
	if err != nil {
		log.Fatal(err)
	}
	return c.Database("coin")
}

func setupRedis() *redis.Client {
	// connect to redis
	url, found := os.LookupEnv("REDIS_ADDR")
	if !found {
		log.Fatal("REDIS_ADDR not found!")
	}
	client := redis.NewClient(&redis.Options{
		Addr: url,
	})
	if _, err := client.Ping().Result(); err != nil {
		log.Fatal("Could not connect to redis:", err)
	}
	return client
}
