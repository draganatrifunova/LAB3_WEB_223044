package mk.ukim.finki.lab1.repository;

import mk.ukim.finki.lab1.bootstrap.DataHolder;
import mk.ukim.finki.lab1.model.Album;
import mk.ukim.finki.lab1.model.Artist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Objects;
import java.util.Optional;
import java.util.List;

@Repository
public interface ArtistRepository extends JpaRepository<Artist, Long>{


}
