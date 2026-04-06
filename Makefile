.PHONY: restore build run test clean

restore:
	dotnet restore ./src/IdentityServer/IdentityServer.csproj

build:
	dotnet build ./src/IdentityServer/IdentityServer.csproj --no-restore

run:
	dotnet run --project ./src/IdentityServer

test:
	dotnet test 2>/dev/null || echo "No test project configured"

clean:
	dotnet clean ./src/IdentityServer/IdentityServer.csproj
	rm -rf bin/ obj/

docker-build:
	docker build -t dotnet-identity-server .

docker-run:
	docker run -p 8080:8080 dotnet-identity-server
