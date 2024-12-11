package mk.ukim.finki.lab1.repository;

import lombok.Data;
import mk.ukim.finki.lab1.bootstrap.DataHolder;
import mk.ukim.finki.lab1.model.Album;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AlbumRepository extends JpaRepository<Album, Long> {

}
