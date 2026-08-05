FROM alpine:3.20
WORKDIR /app
RUN echo "DevSecOps assessment placeholder image" > /app/marker.txt
CMD ["sh", "-c", "cat /app/marker.txt"]
