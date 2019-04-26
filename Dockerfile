FROM gcr.io/cloud-builders/mvn as builder
COPY . /project
WORKDIR /project
RUN mvn -Duser.home=/builder/home -B install

FROM swd847/centos-graal-native-image-rc12 as nativebuilder
COPY --from=builder /project/target /project/
WORKDIR /project
RUN  /opt/graalvm/bin/native-image -J-Djava.util.logging.manager=org.jboss.logmanager.LogManager \
     -J-Dcom.sun.xml.internal.bind.v2.bytecode.ClassTailor.noOptimize=true \
     -H:InitialCollectionPolicy='com.oracle.svm.core.genscavenge.CollectionPolicy$BySpaceAndTime' \
     -jar getting-started-1.0-SNAPSHOT-runner.jar -J-Djava.util.concurrent.ForkJoinPool.common.parallelism=1 \
     -H:+PrintAnalysisCallTree -H:EnableURLProtocols=http \
     -H:-SpawnIsolates -H:-JNI --no-server -H:-UseServiceLoaderFeature -H:+StackTrace \
     && cp  -v getting-started-1.0-SNAPSHOT-runner /tmp/quarkus-runner

FROM  registry.fedoraproject.org/fedora-minimal
RUN mkdir -p /work
COPY --from=nativebuilder /tmp/quarkus-runner /work/application
RUN chmod -R 775 /work
EXPOSE 8080
WORKDIR /work/
ENTRYPOINT ["./application","-Dquarkus.http.host=0.0.0.0"]
